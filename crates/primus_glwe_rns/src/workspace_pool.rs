//! Shared ownership lifecycle for the CRT/DCRT expansion workspaces.

use std::sync::Mutex;

/// Preallocated scratch that each parallel expansion worker borrows exclusively.
/// Numerical layout and representation belong to the concrete workspace owner.
pub(crate) struct WorkspacePool<W> {
    workspaces: Mutex<Vec<W>>,
    capacity: usize,
}

impl<W> WorkspacePool<W> {
    pub(crate) fn new(workspaces: Vec<W>) -> Self {
        let capacity = workspaces.len();
        Self {
            workspaces: Mutex::new(workspaces),
            capacity,
        }
    }

    /// Maximum number of independent jobs that may borrow scratch concurrently.
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    /// Moves one prepared workspace into a guard without allocating; capacity
    /// must cover parallel demand. Drop returns it even if a worker unwinds.
    pub(crate) fn acquire(&self) -> WorkspaceGuard<'_, W> {
        // Drop the mutex guard before reporting exhaustion. A panic while the
        // mutex is held would poison it and could make a live worker's Drop
        // panic again while unwinding.
        let workspace = { self.workspaces.lock().unwrap().pop() };
        let workspace = workspace.expect(
            "coefficient expansion workspace pool capacity is smaller than its parallel demand",
        );
        WorkspaceGuard {
            workspace: Some(workspace),
            pool: self,
        }
    }
}

/// Owns an exclusively borrowed workspace until the worker finishes.
pub(crate) struct WorkspaceGuard<'a, W> {
    workspace: Option<W>,
    pool: &'a WorkspacePool<W>,
}

impl<W> WorkspaceGuard<'_, W> {
    pub(crate) fn workspace_mut(&mut self) -> &mut W {
        self.workspace.as_mut().unwrap()
    }
}

impl<W> Drop for WorkspaceGuard<'_, W> {
    fn drop(&mut self) {
        if let Some(workspace) = self.workspace.take() {
            self.pool.workspaces.lock().unwrap().push(workspace);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WorkspacePool;

    /// A worker may fail after touching scratch. Its guard must return the same
    /// allocation without holding the mutex while the worker unwinds.
    #[test]
    fn worker_unwind_returns_dirty_workspace() {
        let pool = WorkspacePool::new(vec![vec![0u32; 8]]);
        let mut guard = pool.acquire();
        let allocation = guard.workspace_mut().as_ptr();
        drop(guard);
        assert!(
            std::panic::catch_unwind(|| {
                let mut guard = pool.acquire();
                guard.workspace_mut()[0] = 17;
                panic!("simulated worker failure");
            })
            .is_err()
        );
        let mut guard = pool.acquire();
        assert_eq!(guard.workspace_mut().as_ptr(), allocation);
        assert_eq!(guard.workspace_mut()[0], 17);
    }

    #[test]
    fn exhaustion_does_not_poison_live_guards() {
        let pool = WorkspacePool::new(vec![vec![0u32; 8]]);
        let mut live = pool.acquire();
        let allocation = live.workspace_mut().as_ptr();
        assert!(std::panic::catch_unwind(|| pool.acquire()).is_err());
        drop(live);
        let mut recovered = pool.acquire();
        assert_eq!(recovered.workspace_mut().as_ptr(), allocation);
    }
}

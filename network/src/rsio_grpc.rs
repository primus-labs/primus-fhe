// This file is generated. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]
#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]

const METHOD_NODE_SERVICE_STEP_CALL: ::grpcio::Method<
    super::rsio::StepCallRequest,
    super::rsio::StepCallResponse,
> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/rsio.NodeService/StepCall",
    req_mar: ::grpcio::Marshaller {
        ser: ::grpcio::pb_ser,
        de: ::grpcio::pb_de,
    },
    resp_mar: ::grpcio::Marshaller {
        ser: ::grpcio::pb_ser,
        de: ::grpcio::pb_de,
    },
};

#[derive(Clone)]
pub struct NodeServiceClient {
    client: ::grpcio::Client,
}

impl NodeServiceClient {
    pub fn new(channel: ::grpcio::Channel) -> Self {
        NodeServiceClient {
            client: ::grpcio::Client::new(channel),
        }
    }

    pub fn step_call_opt(
        &self,
        req: &super::rsio::StepCallRequest,
        opt: ::grpcio::CallOption,
    ) -> ::grpcio::Result<super::rsio::StepCallResponse> {
        self.client
            .unary_call(&METHOD_NODE_SERVICE_STEP_CALL, req, opt)
    }

    pub fn step_call(
        &self,
        req: &super::rsio::StepCallRequest,
    ) -> ::grpcio::Result<super::rsio::StepCallResponse> {
        self.step_call_opt(req, ::grpcio::CallOption::default())
    }

    pub fn step_call_async_opt(
        &self,
        req: &super::rsio::StepCallRequest,
        opt: ::grpcio::CallOption,
    ) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::rsio::StepCallResponse>> {
        self.client
            .unary_call_async(&METHOD_NODE_SERVICE_STEP_CALL, req, opt)
    }

    pub fn step_call_async(
        &self,
        req: &super::rsio::StepCallRequest,
    ) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::rsio::StepCallResponse>> {
        self.step_call_async_opt(req, ::grpcio::CallOption::default())
    }
    pub fn spawn<F>(&self, f: F)
    where
        F: ::futures::Future<Output = ()> + Send + 'static,
    {
        self.client.spawn(f)
    }
}

pub trait NodeService {
    fn step_call(
        &mut self,
        ctx: ::grpcio::RpcContext,
        _req: super::rsio::StepCallRequest,
        sink: ::grpcio::UnarySink<super::rsio::StepCallResponse>,
    ) {
        grpcio::unimplemented_call!(ctx, sink)
    }
}

pub fn create_node_service<S: NodeService + Send + Clone + 'static>(s: S) -> ::grpcio::Service {
    let mut builder = ::grpcio::ServiceBuilder::new();
    let mut instance = s;
    builder = builder.add_unary_handler(&METHOD_NODE_SERVICE_STEP_CALL, move |ctx, req, resp| {
        instance.step_call(ctx, req, resp)
    });
    builder.build()
}

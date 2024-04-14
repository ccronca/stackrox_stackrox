// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.25.3
// source: api/v1/collector_runtime_configuration_service.proto

package v1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	CollectorRuntimeConfigurationService_GetCollectorRuntimeConfiguration_FullMethodName  = "/v1.CollectorRuntimeConfigurationService/GetCollectorRuntimeConfiguration"
	CollectorRuntimeConfigurationService_PostCollectorRuntimeConfiguration_FullMethodName = "/v1.CollectorRuntimeConfigurationService/PostCollectorRuntimeConfiguration"
)

// CollectorRuntimeConfigurationServiceClient is the client API for CollectorRuntimeConfigurationService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CollectorRuntimeConfigurationServiceClient interface {
	GetCollectorRuntimeConfiguration(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*GetCollectorRuntimeConfigurationResponse, error)
	PostCollectorRuntimeConfiguration(ctx context.Context, in *PostCollectorRuntimeConfigurationRequest, opts ...grpc.CallOption) (*Empty, error)
}

type collectorRuntimeConfigurationServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewCollectorRuntimeConfigurationServiceClient(cc grpc.ClientConnInterface) CollectorRuntimeConfigurationServiceClient {
	return &collectorRuntimeConfigurationServiceClient{cc}
}

func (c *collectorRuntimeConfigurationServiceClient) GetCollectorRuntimeConfiguration(ctx context.Context, in *Empty, opts ...grpc.CallOption) (*GetCollectorRuntimeConfigurationResponse, error) {
	out := new(GetCollectorRuntimeConfigurationResponse)
	err := c.cc.Invoke(ctx, CollectorRuntimeConfigurationService_GetCollectorRuntimeConfiguration_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *collectorRuntimeConfigurationServiceClient) PostCollectorRuntimeConfiguration(ctx context.Context, in *PostCollectorRuntimeConfigurationRequest, opts ...grpc.CallOption) (*Empty, error) {
	out := new(Empty)
	err := c.cc.Invoke(ctx, CollectorRuntimeConfigurationService_PostCollectorRuntimeConfiguration_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CollectorRuntimeConfigurationServiceServer is the server API for CollectorRuntimeConfigurationService service.
// All implementations should embed UnimplementedCollectorRuntimeConfigurationServiceServer
// for forward compatibility
type CollectorRuntimeConfigurationServiceServer interface {
	GetCollectorRuntimeConfiguration(context.Context, *Empty) (*GetCollectorRuntimeConfigurationResponse, error)
	PostCollectorRuntimeConfiguration(context.Context, *PostCollectorRuntimeConfigurationRequest) (*Empty, error)
}

// UnimplementedCollectorRuntimeConfigurationServiceServer should be embedded to have forward compatible implementations.
type UnimplementedCollectorRuntimeConfigurationServiceServer struct {
}

func (UnimplementedCollectorRuntimeConfigurationServiceServer) GetCollectorRuntimeConfiguration(context.Context, *Empty) (*GetCollectorRuntimeConfigurationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCollectorRuntimeConfiguration not implemented")
}
func (UnimplementedCollectorRuntimeConfigurationServiceServer) PostCollectorRuntimeConfiguration(context.Context, *PostCollectorRuntimeConfigurationRequest) (*Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PostCollectorRuntimeConfiguration not implemented")
}

// UnsafeCollectorRuntimeConfigurationServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CollectorRuntimeConfigurationServiceServer will
// result in compilation errors.
type UnsafeCollectorRuntimeConfigurationServiceServer interface {
	mustEmbedUnimplementedCollectorRuntimeConfigurationServiceServer()
}

func RegisterCollectorRuntimeConfigurationServiceServer(s grpc.ServiceRegistrar, srv CollectorRuntimeConfigurationServiceServer) {
	s.RegisterService(&CollectorRuntimeConfigurationService_ServiceDesc, srv)
}

func _CollectorRuntimeConfigurationService_GetCollectorRuntimeConfiguration_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CollectorRuntimeConfigurationServiceServer).GetCollectorRuntimeConfiguration(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CollectorRuntimeConfigurationService_GetCollectorRuntimeConfiguration_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CollectorRuntimeConfigurationServiceServer).GetCollectorRuntimeConfiguration(ctx, req.(*Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func _CollectorRuntimeConfigurationService_PostCollectorRuntimeConfiguration_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PostCollectorRuntimeConfigurationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CollectorRuntimeConfigurationServiceServer).PostCollectorRuntimeConfiguration(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CollectorRuntimeConfigurationService_PostCollectorRuntimeConfiguration_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CollectorRuntimeConfigurationServiceServer).PostCollectorRuntimeConfiguration(ctx, req.(*PostCollectorRuntimeConfigurationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// CollectorRuntimeConfigurationService_ServiceDesc is the grpc.ServiceDesc for CollectorRuntimeConfigurationService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var CollectorRuntimeConfigurationService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "v1.CollectorRuntimeConfigurationService",
	HandlerType: (*CollectorRuntimeConfigurationServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetCollectorRuntimeConfiguration",
			Handler:    _CollectorRuntimeConfigurationService_GetCollectorRuntimeConfiguration_Handler,
		},
		{
			MethodName: "PostCollectorRuntimeConfiguration",
			Handler:    _CollectorRuntimeConfigurationService_PostCollectorRuntimeConfiguration_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/v1/collector_runtime_configuration_service.proto",
}
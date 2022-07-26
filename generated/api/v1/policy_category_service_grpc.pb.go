// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.25.3
// source: api/v1/policy_category_service.proto

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
	PolicyCategoryService_GetPolicyCategory_FullMethodName    = "/v1.PolicyCategoryService/GetPolicyCategory"
	PolicyCategoryService_GetPolicyCategories_FullMethodName  = "/v1.PolicyCategoryService/GetPolicyCategories"
	PolicyCategoryService_PostPolicyCategory_FullMethodName   = "/v1.PolicyCategoryService/PostPolicyCategory"
	PolicyCategoryService_RenamePolicyCategory_FullMethodName = "/v1.PolicyCategoryService/RenamePolicyCategory"
	PolicyCategoryService_DeletePolicyCategory_FullMethodName = "/v1.PolicyCategoryService/DeletePolicyCategory"
)

// PolicyCategoryServiceClient is the client API for PolicyCategoryService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PolicyCategoryServiceClient interface {
	// GetPolicyCategory returns the requested policy category by ID.
	GetPolicyCategory(ctx context.Context, in *ResourceByID, opts ...grpc.CallOption) (*PolicyCategory, error)
	// GetPolicyCategories returns the list of policy categories
	GetPolicyCategories(ctx context.Context, in *RawQuery, opts ...grpc.CallOption) (*GetPolicyCategoriesResponse, error)
	// PostPolicyCategory creates a new policy category
	PostPolicyCategory(ctx context.Context, in *PostPolicyCategoryRequest, opts ...grpc.CallOption) (*PolicyCategory, error)
	// RenamePolicyCategory renames the given policy category.
	RenamePolicyCategory(ctx context.Context, in *RenamePolicyCategoryRequest, opts ...grpc.CallOption) (*PolicyCategory, error)
	// DeletePolicyCategory removes the given policy category.
	DeletePolicyCategory(ctx context.Context, in *DeletePolicyCategoryRequest, opts ...grpc.CallOption) (*Empty, error)
}

type policyCategoryServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewPolicyCategoryServiceClient(cc grpc.ClientConnInterface) PolicyCategoryServiceClient {
	return &policyCategoryServiceClient{cc}
}

func (c *policyCategoryServiceClient) GetPolicyCategory(ctx context.Context, in *ResourceByID, opts ...grpc.CallOption) (*PolicyCategory, error) {
	out := new(PolicyCategory)
	err := c.cc.Invoke(ctx, PolicyCategoryService_GetPolicyCategory_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *policyCategoryServiceClient) GetPolicyCategories(ctx context.Context, in *RawQuery, opts ...grpc.CallOption) (*GetPolicyCategoriesResponse, error) {
	out := new(GetPolicyCategoriesResponse)
	err := c.cc.Invoke(ctx, PolicyCategoryService_GetPolicyCategories_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *policyCategoryServiceClient) PostPolicyCategory(ctx context.Context, in *PostPolicyCategoryRequest, opts ...grpc.CallOption) (*PolicyCategory, error) {
	out := new(PolicyCategory)
	err := c.cc.Invoke(ctx, PolicyCategoryService_PostPolicyCategory_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *policyCategoryServiceClient) RenamePolicyCategory(ctx context.Context, in *RenamePolicyCategoryRequest, opts ...grpc.CallOption) (*PolicyCategory, error) {
	out := new(PolicyCategory)
	err := c.cc.Invoke(ctx, PolicyCategoryService_RenamePolicyCategory_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *policyCategoryServiceClient) DeletePolicyCategory(ctx context.Context, in *DeletePolicyCategoryRequest, opts ...grpc.CallOption) (*Empty, error) {
	out := new(Empty)
	err := c.cc.Invoke(ctx, PolicyCategoryService_DeletePolicyCategory_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PolicyCategoryServiceServer is the server API for PolicyCategoryService service.
// All implementations should embed UnimplementedPolicyCategoryServiceServer
// for forward compatibility
type PolicyCategoryServiceServer interface {
	// GetPolicyCategory returns the requested policy category by ID.
	GetPolicyCategory(context.Context, *ResourceByID) (*PolicyCategory, error)
	// GetPolicyCategories returns the list of policy categories
	GetPolicyCategories(context.Context, *RawQuery) (*GetPolicyCategoriesResponse, error)
	// PostPolicyCategory creates a new policy category
	PostPolicyCategory(context.Context, *PostPolicyCategoryRequest) (*PolicyCategory, error)
	// RenamePolicyCategory renames the given policy category.
	RenamePolicyCategory(context.Context, *RenamePolicyCategoryRequest) (*PolicyCategory, error)
	// DeletePolicyCategory removes the given policy category.
	DeletePolicyCategory(context.Context, *DeletePolicyCategoryRequest) (*Empty, error)
}

// UnimplementedPolicyCategoryServiceServer should be embedded to have forward compatible implementations.
type UnimplementedPolicyCategoryServiceServer struct {
}

func (UnimplementedPolicyCategoryServiceServer) GetPolicyCategory(context.Context, *ResourceByID) (*PolicyCategory, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPolicyCategory not implemented")
}
func (UnimplementedPolicyCategoryServiceServer) GetPolicyCategories(context.Context, *RawQuery) (*GetPolicyCategoriesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPolicyCategories not implemented")
}
func (UnimplementedPolicyCategoryServiceServer) PostPolicyCategory(context.Context, *PostPolicyCategoryRequest) (*PolicyCategory, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PostPolicyCategory not implemented")
}
func (UnimplementedPolicyCategoryServiceServer) RenamePolicyCategory(context.Context, *RenamePolicyCategoryRequest) (*PolicyCategory, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RenamePolicyCategory not implemented")
}
func (UnimplementedPolicyCategoryServiceServer) DeletePolicyCategory(context.Context, *DeletePolicyCategoryRequest) (*Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeletePolicyCategory not implemented")
}

// UnsafePolicyCategoryServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PolicyCategoryServiceServer will
// result in compilation errors.
type UnsafePolicyCategoryServiceServer interface {
	mustEmbedUnimplementedPolicyCategoryServiceServer()
}

func RegisterPolicyCategoryServiceServer(s grpc.ServiceRegistrar, srv PolicyCategoryServiceServer) {
	s.RegisterService(&PolicyCategoryService_ServiceDesc, srv)
}

func _PolicyCategoryService_GetPolicyCategory_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ResourceByID)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyCategoryServiceServer).GetPolicyCategory(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PolicyCategoryService_GetPolicyCategory_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyCategoryServiceServer).GetPolicyCategory(ctx, req.(*ResourceByID))
	}
	return interceptor(ctx, in, info, handler)
}

func _PolicyCategoryService_GetPolicyCategories_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RawQuery)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyCategoryServiceServer).GetPolicyCategories(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PolicyCategoryService_GetPolicyCategories_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyCategoryServiceServer).GetPolicyCategories(ctx, req.(*RawQuery))
	}
	return interceptor(ctx, in, info, handler)
}

func _PolicyCategoryService_PostPolicyCategory_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PostPolicyCategoryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyCategoryServiceServer).PostPolicyCategory(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PolicyCategoryService_PostPolicyCategory_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyCategoryServiceServer).PostPolicyCategory(ctx, req.(*PostPolicyCategoryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PolicyCategoryService_RenamePolicyCategory_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RenamePolicyCategoryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyCategoryServiceServer).RenamePolicyCategory(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PolicyCategoryService_RenamePolicyCategory_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyCategoryServiceServer).RenamePolicyCategory(ctx, req.(*RenamePolicyCategoryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _PolicyCategoryService_DeletePolicyCategory_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeletePolicyCategoryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PolicyCategoryServiceServer).DeletePolicyCategory(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: PolicyCategoryService_DeletePolicyCategory_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PolicyCategoryServiceServer).DeletePolicyCategory(ctx, req.(*DeletePolicyCategoryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// PolicyCategoryService_ServiceDesc is the grpc.ServiceDesc for PolicyCategoryService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var PolicyCategoryService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "v1.PolicyCategoryService",
	HandlerType: (*PolicyCategoryServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetPolicyCategory",
			Handler:    _PolicyCategoryService_GetPolicyCategory_Handler,
		},
		{
			MethodName: "GetPolicyCategories",
			Handler:    _PolicyCategoryService_GetPolicyCategories_Handler,
		},
		{
			MethodName: "PostPolicyCategory",
			Handler:    _PolicyCategoryService_PostPolicyCategory_Handler,
		},
		{
			MethodName: "RenamePolicyCategory",
			Handler:    _PolicyCategoryService_RenamePolicyCategory_Handler,
		},
		{
			MethodName: "DeletePolicyCategory",
			Handler:    _PolicyCategoryService_DeletePolicyCategory_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/v1/policy_category_service.proto",
}
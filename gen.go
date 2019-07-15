package dockervpp

// TEMPLATE for VPP API generation
// Copy this to your project root and change the package name before running go generate
// This file generates the VPP client code from the installed VPP headers

// CORE API
//go:generate binapi-generator --input-dir=/usr/share/vpp/api/core --output-dir=bin_api

// PLUGIN API
//go:generate binapi-generator --input-dir=/usr/share/vpp/api/plugins --output-dir=bin_api

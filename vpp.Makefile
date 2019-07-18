# This is a template for generating the VPP API client code
# Copy this to your project root or integrate this into your build system
# Run `make api`, if running VPP version != 19.04
#

.PHONY: api
all: api

binapi-gen:
	go get -u git.fd.io/govpp.git
	cd $(GOPATH)/src/git.fd.io/govpp.git && make install
	rm -rf $(GOPATH)/src/git.fd.io/govpp.git

api: binapi-gen
	go generate

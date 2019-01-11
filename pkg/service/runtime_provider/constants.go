// Copyright 2018 The OpenPitrix Authors. All rights reserved.
// Use of this source code is governed by a Apache license
// that can be found in the LICENSE file.

package runtime_provider

const (
	Provider       = "aws"
	ProviderConfig = `
api_server: .*.amazonaws.com
zone: .*
image_name: amzn2-ami-hvm-2.0.20180622.1-x86_64-gp2
image_url: https://openpitrix.pek3a.qingstor.com/image/amazon-linux.tar.gz
provider_type: vmbased
`
)

const (
	DefaultVolumeClass = 1
	DefaultDevice      = "/dev/sdf"
	DefaultZone        = "us-east-2"
)

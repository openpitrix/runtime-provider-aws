// Copyright 2018 The OpenPitrix Authors. All rights reserved.
// Use of this source code is governed by a Apache license
// that can be found in the LICENSE file.

package runtime_provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"

	runtimeclient "openpitrix.io/openpitrix/pkg/client/runtime"
	"openpitrix.io/openpitrix/pkg/constants"
	"openpitrix.io/openpitrix/pkg/logger"
	"openpitrix.io/openpitrix/pkg/models"
	"openpitrix.io/openpitrix/pkg/pb"
	"openpitrix.io/openpitrix/pkg/pi"
	"openpitrix.io/openpitrix/pkg/plugins/vmbased"
	"openpitrix.io/openpitrix/pkg/util/funcutil"
	"openpitrix.io/openpitrix/pkg/util/jsonutil"
	"openpitrix.io/openpitrix/pkg/util/pbutil"
)

var MyProvider = constants.ProviderAWS

type ProviderHandler struct {
	vmbased.FrameHandler
}

func (p *ProviderHandler) initAWSSession(ctx context.Context, runtimeUrl, runtimeCredential, zone string) (*session.Session, error) {
	credential := new(vmbased.Credential)
	err := jsonutil.Decode([]byte(runtimeCredential), credential)
	if err != nil {
		logger.Error(ctx, "Parse [%s] credential failed: %+v", MyProvider, err)
		return nil, err
	}

	creds := credentials.NewStaticCredentials(credential.AccessKeyId, credential.SecretAccessKey, "")
	config := &aws.Config{
		Region:      aws.String(zone),
		Endpoint:    aws.String(""),
		Credentials: creds,
	}

	return session.NewSession(config)
}

func (p *ProviderHandler) initSession(ctx context.Context, runtimeId string) (*session.Session, error) {
	runtime, err := runtimeclient.NewRuntime(ctx, runtimeId)
	if err != nil {
		return nil, err
	}

	return p.initAWSSession(ctx, runtime.RuntimeUrl, runtime.RuntimeCredentialContent, runtime.Zone)
}

func (p *ProviderHandler) initInstanceService(ctx context.Context, runtimeId string) (ec2iface.EC2API, error) {
	awsSession, err := p.initSession(ctx, runtimeId)
	if err != nil {
		logger.Error(ctx, "Init %s api session failed: %+v", MyProvider, err)
		return nil, err
	}

	abc := ec2.New(awsSession)

	return abc, nil
}

func (p *ProviderHandler) RunInstances(ctx context.Context, task *models.Task) (*models.Task, error) {
	if task.Directive == "" {
		logger.Warn(ctx, "Skip task without directive")
		return task, nil
	}
	instance, err := models.NewInstance(task.Directive)
	if err != nil {
		return task, err
	}
	instanceService, err := p.initInstanceService(ctx, instance.RuntimeId)
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return task, err
	}

	instanceType, err := ConvertToInstanceType(instance.Cpu, instance.Memory)
	if err != nil {
		logger.Error(ctx, "Could not find an aws instance type: %+v", err)
		return task, err
	}

	logger.Info(ctx, "RunInstances with name [%s] instance type [%s]", instance.Name, instanceType)

	tag := ec2.Tag{
		Key:   aws.String("Name"),
		Value: aws.String(instance.Name),
	}

	tagSpec := ec2.TagSpecification{
		ResourceType: aws.String("instance"),
		Tags:         []*ec2.Tag{&tag},
	}

	input := ec2.RunInstancesInput{
		ImageId:           aws.String(instance.ImageId),
		InstanceType:      aws.String(instanceType),
		TagSpecifications: []*ec2.TagSpecification{&tagSpec},
		SubnetId:          aws.String(instance.Subnet),
		Placement:         &ec2.Placement{AvailabilityZone: aws.String(instance.Zone)},
		MaxCount:          aws.Int64(1),
		MinCount:          aws.Int64(1),
	}

	keyName, ok := pi.Global().GlobalConfig().Runtime[Provider].AdvancedOptions[AdvancedOptionsKeyName]
	if ok && len(keyName.(string)) > 0 {
		input.KeyName = aws.String(keyName.(string))
	}

	if instance.NeedUserData == 1 {
		input.UserData = aws.String(instance.UserDataValue)
	}

	logger.Debug(ctx, "RunInstances with input: %s", jsonutil.ToString(input))
	output, err := instanceService.RunInstances(&input)
	if err != nil {
		logger.Error(ctx, "Send RunInstances to %s failed: %+v", MyProvider, err)
		return task, err
	}

	if len(output.Instances) == 0 {
		logger.Error(ctx, "Send RunInstances to %s failed with 0 output instances", MyProvider)
		return task, fmt.Errorf("send RunInstances to %s failed with 0 output instances", MyProvider)
	}

	logger.Debug(ctx, "RunInstances get output: %s", jsonutil.ToString(output))

	instance.InstanceId = aws.StringValue(output.Instances[0].InstanceId)

	// write back
	task.Directive = jsonutil.ToString(instance)

	return task, nil
}

func (p *ProviderHandler) StopInstances(ctx context.Context, task *models.Task) (*models.Task, error) {
	if task.Directive == "" {
		logger.Warn(ctx, "Skip task without directive")
		return task, nil
	}
	instance, err := models.NewInstance(task.Directive)
	if err != nil {
		return task, err
	}
	if instance.InstanceId == "" {
		logger.Warn(ctx, "Skip task without instance id")
		return task, nil
	}
	instanceService, err := p.initInstanceService(ctx, instance.RuntimeId)
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return task, err
	}

	describeOutput, err := instanceService.DescribeInstances(
		&ec2.DescribeInstancesInput{
			InstanceIds: aws.StringSlice([]string{instance.InstanceId}),
		})
	if err != nil {
		logger.Error(ctx, "Send DescribeInstances to %s failed: %+v", MyProvider, err)
		return task, err
	}

	if len(describeOutput.Reservations) == 0 {
		return task, fmt.Errorf("instance with id [%s] not exist", instance.InstanceId)
	}

	if len(describeOutput.Reservations[0].Instances) == 0 {
		return task, fmt.Errorf("instance with id [%s] not exist", instance.InstanceId)
	}

	status := aws.StringValue(describeOutput.Reservations[0].Instances[0].State.Name)

	if status == constants.StatusStopped {
		logger.Warn(ctx, "Instance [%s] has already been [%s], do nothing", instance.InstanceId, status)
		return task, nil
	}

	logger.Info(ctx, "StopInstances [%s]", instance.Name)

	_, err = instanceService.StopInstances(
		&ec2.StopInstancesInput{
			InstanceIds: aws.StringSlice([]string{instance.InstanceId}),
		})
	if err != nil {
		logger.Error(ctx, "Send StopInstances to %s failed: %+v", MyProvider, err)
		return task, err
	}

	// write back
	task.Directive = jsonutil.ToString(instance)

	return task, nil
}

func (p *ProviderHandler) StartInstances(ctx context.Context, task *models.Task) (*models.Task, error) {
	if task.Directive == "" {
		logger.Warn(ctx, "Skip task without directive")
		return task, nil
	}
	instance, err := models.NewInstance(task.Directive)
	if err != nil {
		return task, err
	}
	if instance.InstanceId == "" {
		logger.Warn(ctx, "Skip task without instance id")
		return task, nil
	}
	instanceService, err := p.initInstanceService(ctx, instance.RuntimeId)
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return task, err
	}

	describeOutput, err := instanceService.DescribeInstances(
		&ec2.DescribeInstancesInput{
			InstanceIds: aws.StringSlice([]string{instance.InstanceId}),
		})
	if err != nil {
		logger.Error(ctx, "Send DescribeInstances to %s failed: %+v", MyProvider, err)
		return task, err
	}

	if len(describeOutput.Reservations) == 0 {
		return task, fmt.Errorf("instance with id [%s] not exist", instance.InstanceId)
	}

	if len(describeOutput.Reservations[0].Instances) == 0 {
		return task, fmt.Errorf("instance with id [%s] not exist", instance.InstanceId)
	}

	status := aws.StringValue(describeOutput.Reservations[0].Instances[0].State.Name)

	if status == constants.StatusRunning {
		logger.Warn(ctx, "Instance [%s] has already been [%s], do nothing", instance.InstanceId, status)
		return task, nil
	}

	logger.Info(ctx, "StartInstances [%s]", instance.Name)

	_, err = instanceService.StartInstances(
		&ec2.StartInstancesInput{
			InstanceIds: aws.StringSlice([]string{instance.InstanceId}),
		})
	if err != nil {
		logger.Error(ctx, "Send StartInstances to %s failed: %+v", MyProvider, err)
		return task, err
	}

	// write back
	task.Directive = jsonutil.ToString(instance)

	return task, nil
}

func (p *ProviderHandler) DeleteInstances(ctx context.Context, task *models.Task) (*models.Task, error) {
	if task.Directive == "" {
		logger.Warn(ctx, "Skip task without directive")
		return task, nil
	}
	instance, err := models.NewInstance(task.Directive)
	if err != nil {
		return task, err
	}
	if instance.InstanceId == "" {
		logger.Warn(ctx, "Skip task without instance id")
		return task, nil
	}
	instanceService, err := p.initInstanceService(ctx, instance.RuntimeId)
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return task, err
	}

	describeOutput, err := instanceService.DescribeInstances(
		&ec2.DescribeInstancesInput{
			InstanceIds: aws.StringSlice([]string{instance.InstanceId}),
		})
	if err != nil {
		if strings.Contains(err.Error(), "not exist") {
			logger.Warn(nil, "Delete instance failed, %+v", err)
			return task, nil
		}
		logger.Error(ctx, "Send DescribeInstances to %s failed: %+v", MyProvider, err)
		return task, err
	}

	if len(describeOutput.Reservations) == 0 {
		logger.Warn(nil, "Instance with id [%s] not exist", instance.InstanceId)
		return task, nil
	}

	if len(describeOutput.Reservations[0].Instances) == 0 {
		logger.Warn(nil, "Instance with id [%s] not exist", instance.InstanceId)
		return task, nil
	}

	status := aws.StringValue(describeOutput.Reservations[0].Instances[0].State.Name)

	if status == constants.StatusTerminated {
		logger.Warn(ctx, "Instance [%s] has already been [%s], do nothing", instance.InstanceId, status)
		return task, nil
	}

	logger.Info(ctx, "TerminateInstances [%s]", instance.Name)

	_, err = instanceService.TerminateInstances(
		&ec2.TerminateInstancesInput{
			InstanceIds: aws.StringSlice([]string{instance.InstanceId}),
		})
	if err != nil {
		logger.Error(ctx, "Send TerminateInstances to %s failed: %+v", MyProvider, err)
		return task, err
	}

	// write back
	task.Directive = jsonutil.ToString(instance)

	return task, nil
}

func (p *ProviderHandler) ResizeInstances(ctx context.Context, task *models.Task) (*models.Task, error) {
	if task.Directive == "" {
		logger.Warn(ctx, "Skip task without directive")
		return task, nil
	}
	instance, err := models.NewInstance(task.Directive)
	if err != nil {
		return task, err
	}
	if instance.InstanceId == "" {
		logger.Warn(ctx, "Skip task without instance id")
		return task, nil
	}
	instanceService, err := p.initInstanceService(ctx, instance.RuntimeId)
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return task, err
	}
	describeOutput, err := instanceService.DescribeInstances(
		&ec2.DescribeInstancesInput{
			InstanceIds: aws.StringSlice([]string{instance.InstanceId}),
		})
	if err != nil {
		logger.Error(ctx, "Send DescribeInstances to %s failed: %+v", MyProvider, err)
		return task, err
	}

	if len(describeOutput.Reservations) == 0 {
		return task, fmt.Errorf("instance with id [%s] not exist", instance.InstanceId)
	}

	if len(describeOutput.Reservations[0].Instances) == 0 {
		return task, fmt.Errorf("instance with id [%s] not exist", instance.InstanceId)
	}

	status := aws.StringValue(describeOutput.Reservations[0].Instances[0].State.Name)

	if status != constants.StatusStopped {
		logger.Warn(ctx, "Instance [%s] is in status [%s], can not resize", instance.InstanceId, status)
		return task, fmt.Errorf("instance [%s] is in status [%s], can not resize", instance.InstanceId, status)
	}

	instanceType, err := ConvertToInstanceType(instance.Cpu, instance.Memory)
	if err != nil {
		logger.Error(ctx, "Could not find an aws instance type: %+v", err)
		return task, err
	}

	logger.Info(ctx, "ResizeInstances [%s] with instance type [%s]", instance.Name, instanceType)

	_, err = instanceService.ModifyInstanceAttribute(
		&ec2.ModifyInstanceAttributeInput{
			InstanceId: aws.String(instance.InstanceId),
			InstanceType: &ec2.AttributeValue{
				Value: aws.String(instanceType),
			},
		},
	)
	if err != nil {
		logger.Error(ctx, "Send ResizeInstances to %s failed: %+v", MyProvider, err)
		return task, err
	}

	// write back
	task.Directive = jsonutil.ToString(instance)
	return task, nil
}

func (p *ProviderHandler) CreateVolumes(ctx context.Context, task *models.Task) (*models.Task, error) {
	if task.Directive == "" {
		logger.Warn(ctx, "Skip task without directive")
		return task, nil
	}
	volume, err := models.NewVolume(task.Directive)
	if err != nil {
		return task, err
	}
	instanceService, err := p.initInstanceService(ctx, volume.RuntimeId)
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return task, err
	}

	tag := ec2.Tag{
		Key:   aws.String("Name"),
		Value: aws.String(volume.Name),
	}

	tagSpec := ec2.TagSpecification{
		ResourceType: aws.String("volume"),
		Tags:         []*ec2.Tag{&tag},
	}

	volumeType, err := ConvertToVolumeType(DefaultVolumeClass)
	if err != nil {
		return task, err
	}

	logger.Info(ctx, "CreateVolumes with name [%s] volume type [%s]", volume.Name, volumeType)

	input := ec2.CreateVolumeInput{
		AvailabilityZone:  aws.String(volume.Zone),
		Size:              aws.Int64(int64(volume.Size)),
		VolumeType:        aws.String(volumeType),
		TagSpecifications: []*ec2.TagSpecification{&tagSpec},
	}

	output, err := instanceService.CreateVolume(&input)
	if err != nil {
		logger.Error(ctx, "Send CreateVolumes to %s failed: %+v", MyProvider, err)
		return task, err
	}

	volume.VolumeId = aws.StringValue(output.VolumeId)

	// write back
	task.Directive = jsonutil.ToString(volume)

	return task, nil
}

func (p *ProviderHandler) DetachVolumes(ctx context.Context, task *models.Task) (*models.Task, error) {
	if task.Directive == "" {
		logger.Warn(ctx, "Skip task without directive")
		return task, nil
	}
	volume, err := models.NewVolume(task.Directive)
	if err != nil {
		return task, err
	}
	if volume.VolumeId == "" {
		logger.Warn(ctx, "Skip task without volume id")
		return task, nil
	}
	if volume.InstanceId == "" {
		logger.Warn(ctx, "Skip task without instance id")
		return task, nil
	}
	instanceService, err := p.initInstanceService(ctx, volume.RuntimeId)
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return task, err
	}

	describeOutput, err := instanceService.DescribeVolumes(
		&ec2.DescribeVolumesInput{
			VolumeIds: aws.StringSlice([]string{volume.VolumeId}),
		})
	if err != nil {
		logger.Error(ctx, "Send DescribeVolumes to %s failed: %+v", MyProvider, err)
		return task, err
	}

	if len(describeOutput.Volumes) == 0 {
		return task, fmt.Errorf("volume with id [%s] not exist", volume.VolumeId)
	}

	status := aws.StringValue(describeOutput.Volumes[0].State)
	if status == constants.StatusAvailable {
		logger.Warn(ctx, "Volume [%s] is in status [%s], no need to detach.", volume.VolumeId, status)
		return task, nil
	}

	logger.Info(ctx, "DetachVolume [%s] from instance with id [%s]", volume.Name, volume.InstanceId)

	_, err = instanceService.DetachVolume(
		&ec2.DetachVolumeInput{
			InstanceId: aws.String(volume.InstanceId),
			VolumeId:   aws.String(volume.VolumeId),
		})
	if err != nil {
		logger.Error(ctx, "Send DetachVolumes to %s failed: %+v", MyProvider, err)
		return task, err
	}

	// write back
	task.Directive = jsonutil.ToString(volume)

	return task, nil
}

func (p *ProviderHandler) AttachVolumes(ctx context.Context, task *models.Task) (*models.Task, error) {
	if task.Directive == "" {
		logger.Warn(ctx, "Skip task without directive")
		return task, nil
	}
	volume, err := models.NewVolume(task.Directive)
	if err != nil {
		return task, err
	}
	if volume.VolumeId == "" {
		logger.Warn(ctx, "Skip task without volume id")
		return task, nil
	}
	if volume.InstanceId == "" {
		logger.Warn(ctx, "Skip task without instance id")
		return task, nil
	}
	instanceService, err := p.initInstanceService(ctx, volume.RuntimeId)
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return task, err
	}

	logger.Info(ctx, "AttachVolume [%s] to instance with id [%s]", volume.Name, volume.InstanceId)

	_, err = instanceService.AttachVolume(
		&ec2.AttachVolumeInput{
			InstanceId: aws.String(volume.InstanceId),
			VolumeId:   aws.String(volume.VolumeId),
			Device:     aws.String(DefaultDevice),
		})
	if err != nil {
		logger.Error(ctx, "Send AttachVolumes to %s failed: %+v", MyProvider, err)
		return task, err
	}

	// write back
	task.Directive = jsonutil.ToString(volume)

	return task, nil
}

func (p *ProviderHandler) DeleteVolumes(ctx context.Context, task *models.Task) (*models.Task, error) {
	if task.Directive == "" {
		logger.Warn(ctx, "Skip task without directive")
		return task, nil
	}
	volume, err := models.NewVolume(task.Directive)
	if err != nil {
		return task, err
	}
	if volume.VolumeId == "" {
		logger.Warn(ctx, "Skip task without volume id")
		return task, nil
	}
	instanceService, err := p.initInstanceService(ctx, volume.RuntimeId)
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return task, err
	}

	describeOutput, err := instanceService.DescribeVolumes(
		&ec2.DescribeVolumesInput{
			VolumeIds: aws.StringSlice([]string{volume.VolumeId}),
		})
	if err != nil {
		if strings.Contains(err.Error(), "not exist") {
			logger.Warn(nil, "Delete volume failed, %+v", err)
			return task, nil
		}
		logger.Error(ctx, "Send DescribeVolumes to %s failed: %+v", MyProvider, err)
		return task, err
	}

	if len(describeOutput.Volumes) == 0 {
		logger.Warn(nil, "Volume with id [%s] not exist", volume.VolumeId)
		return task, nil
	}

	logger.Info(ctx, "DeleteVolume [%s]", volume.Name)

	_, err = instanceService.DeleteVolume(
		&ec2.DeleteVolumeInput{
			VolumeId: aws.String(volume.VolumeId),
		})
	if err != nil {
		logger.Error(ctx, "Send DeleteVolumes to %s failed: %+v", MyProvider, err)
		return task, err
	}

	// write back
	task.Directive = jsonutil.ToString(volume)

	return task, nil
}

func (p *ProviderHandler) ResizeVolumes(ctx context.Context, task *models.Task) (*models.Task, error) {
	if task.Directive == "" {
		logger.Warn(ctx, "Skip task without directive")
		return task, nil
	}
	volume, err := models.NewVolume(task.Directive)
	if err != nil {
		return task, err
	}
	if volume.VolumeId == "" {
		logger.Warn(ctx, "Skip task without volume")
		return task, nil
	}
	instanceService, err := p.initInstanceService(ctx, volume.RuntimeId)
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return task, err
	}

	describeOutput, err := instanceService.DescribeVolumes(
		&ec2.DescribeVolumesInput{
			VolumeIds: aws.StringSlice([]string{volume.VolumeId}),
		})
	if err != nil {
		logger.Error(ctx, "Send DescribeVolumes to %s failed: %+v", MyProvider, err)
		return task, err
	}

	if len(describeOutput.Volumes) == 0 {
		return task, fmt.Errorf("volume with id [%s] not exist", volume.VolumeId)
	}

	status := aws.StringValue(describeOutput.Volumes[0].State)
	if status != constants.StatusAvailable {
		logger.Warn(ctx, "Volume [%s] is in status [%s], can not resize.", volume.VolumeId, status)
		return task, fmt.Errorf("volume [%s] is in status [%s], can not resize", volume.VolumeId, status)
	}

	logger.Info(ctx, "ResizeVolumes [%s] with size [%d]", volume.Name, volume.Size)

	_, err = instanceService.ModifyVolume(
		&ec2.ModifyVolumeInput{
			VolumeId: aws.String(volume.VolumeId),
			Size:     aws.Int64(int64(volume.Size)),
		},
	)
	if err != nil {
		logger.Error(ctx, "Send ResizeVolumes to %s failed: %+v", MyProvider, err)
		return task, err
	}

	// write back
	task.Directive = jsonutil.ToString(volume)
	return task, nil
}

func (p *ProviderHandler) waitInstanceVolumeAndNetwork(ctx context.Context, instanceService ec2iface.EC2API, task *models.Task, instanceId, volumeId string, timeout time.Duration, waitInterval time.Duration) (*ec2.Instance, *models.Task, error) {
	logger.Debug(ctx, "Waiting for volume [%s] attached to Instance [%s]", volumeId, instanceId)
	if volumeId != "" {
		task, err := p.AttachVolumes(ctx, task)
		if err != nil {
			logger.Debug(ctx, "Attach volume [%s] to Instance [%s] failed: %+v", volumeId, instanceId, err)
			return nil, task, err
		}

		task, err = p.WaitAttachVolumes(ctx, task)
		if err != nil {
			logger.Debug(ctx, "Waiting for volume [%s] attached to Instance [%s] failed: %+v", volumeId, instanceId, err)
			return nil, task, err
		}
	}

	var ins *ec2.Instance
	err := funcutil.WaitForSpecificOrError(func() (bool, error) {
		describeOutput, err := instanceService.DescribeInstances(
			&ec2.DescribeInstancesInput{
				InstanceIds: aws.StringSlice([]string{instanceId}),
			},
		)
		if err != nil {
			return false, err
		}

		if len(describeOutput.Reservations) == 0 {
			return false, fmt.Errorf("instance with id [%s] not exist", instanceId)
		}
		if len(describeOutput.Reservations[0].Instances) == 0 {
			return false, fmt.Errorf("instance with id [%s] not exist", instanceId)
		}

		instance := describeOutput.Reservations[0].Instances[0]

		if instance.PrivateIpAddress == nil || aws.StringValue(instance.PrivateIpAddress) == "" {
			return false, nil
		}
		if instance.PublicIpAddress == nil || aws.StringValue(instance.PublicIpAddress) == "" {
			return false, nil
		}
		if volumeId != "" {
			if len(instance.BlockDeviceMappings) == 0 {
				return false, nil
			}

			found := false
			for _, dev := range instance.BlockDeviceMappings {
				if aws.StringValue(dev.Ebs.VolumeId) == volumeId {
					found = true
				}
			}

			if !found {
				return false, nil
			}
		}

		ins = instance
		logger.Debug(ctx, "Instance [%s] get IP address [%s]", instanceId, *ins.PrivateIpAddress)
		return true, nil
	}, timeout, waitInterval)
	return ins, task, err
}

func (p *ProviderHandler) WaitRunInstances(ctx context.Context, task *models.Task) (*models.Task, error) {
	if task.Directive == "" {
		logger.Warn(ctx, "Skip task without directive")
		return task, nil
	}
	instance, err := models.NewInstance(task.Directive)
	if err != nil {
		return task, err
	}
	if instance.InstanceId == "" {
		logger.Warn(ctx, "Skip task without instance id")
		return task, nil
	}
	instanceService, err := p.initInstanceService(ctx, instance.RuntimeId)
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return task, err
	}

	task, err = p.WaitInstanceState(ctx, task, constants.StatusRunning)
	if err != nil {
		logger.Error(ctx, "Wait %s job [%s] failed: %+v", MyProvider, instance.TargetJobId, err)
		return task, err
	}

	output, task, err := p.waitInstanceVolumeAndNetwork(ctx, instanceService, task, instance.InstanceId, instance.VolumeId, task.GetTimeout(constants.WaitTaskTimeout), constants.WaitTaskInterval)
	if err != nil {
		logger.Error(ctx, "Wait %s instance [%s] network failed: %+v", MyProvider, instance.InstanceId, err)
		return task, err
	}

	instance.PrivateIp = aws.StringValue(output.PrivateIpAddress)
	instance.Eip = aws.StringValue(output.PublicIpAddress)
	if len(output.BlockDeviceMappings) > 0 {
		for _, dev := range output.BlockDeviceMappings {
			if aws.StringValue(dev.Ebs.VolumeId) == instance.VolumeId {
				instance.Device = aws.StringValue(dev.DeviceName)
			}
		}
	}

	// write back
	task.Directive = jsonutil.ToString(instance)

	logger.Debug(ctx, "WaitRunInstances task [%s] directive: %s", task.TaskId, task.Directive)

	return task, nil
}

func (p *ProviderHandler) WaitInstanceState(ctx context.Context, task *models.Task, state string) (*models.Task, error) {
	if task.Directive == "" {
		logger.Warn(ctx, "Skip task without directive")
		return task, nil
	}
	instance, err := models.NewInstance(task.Directive)
	if err != nil {
		return task, err
	}
	if instance.InstanceId == "" {
		logger.Warn(ctx, "Skip task without instance id")
		return task, nil
	}
	instanceService, err := p.initInstanceService(ctx, instance.RuntimeId)
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return task, err
	}

	err = funcutil.WaitForSpecificOrError(func() (bool, error) {
		input := ec2.DescribeInstancesInput{
			InstanceIds: []*string{aws.String(instance.InstanceId)},
		}

		output, err := instanceService.DescribeInstances(&input)
		if err != nil {
			return true, err
		}

		if len(output.Reservations) == 0 {
			return true, fmt.Errorf("instance with id [%s] not exist", instance.InstanceId)
		}

		if len(output.Reservations[0].Instances) == 0 {
			return true, fmt.Errorf("instance with id [%s] not exist", instance.InstanceId)
		}

		if aws.StringValue(output.Reservations[0].Instances[0].State.Name) == state {
			return true, nil
		}

		return false, nil
	}, task.GetTimeout(constants.WaitTaskTimeout), constants.WaitTaskInterval)
	if err != nil {
		logger.Error(ctx, "Wait %s instance [%s] status become to [%s] failed: %+v", MyProvider, instance.InstanceId, state, err)
		return task, err
	}

	logger.Info(ctx, "Wait %s instance [%s] status become to [%s] success", MyProvider, instance.InstanceId, state)

	return task, nil
}

func (p *ProviderHandler) WaitVolumeState(ctx context.Context, task *models.Task, state string) (*models.Task, error) {
	if task.Directive == "" {
		logger.Warn(ctx, "Skip task without directive")
		return task, nil
	}
	volume, err := models.NewVolume(task.Directive)
	if err != nil {
		return task, err
	}
	if volume.VolumeId == "" {
		logger.Warn(ctx, "Skip task without volume id")
		return task, nil
	}
	instanceService, err := p.initInstanceService(ctx, volume.RuntimeId)
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return task, err
	}

	err = funcutil.WaitForSpecificOrError(func() (bool, error) {
		input := ec2.DescribeVolumesInput{
			VolumeIds: []*string{aws.String(volume.VolumeId)},
		}

		output, err := instanceService.DescribeVolumes(&input)
		if err != nil {
			return true, err
		}

		if len(output.Volumes) == 0 {
			return true, fmt.Errorf("volume [%s] not found", volume.VolumeId)
		}

		if aws.StringValue(output.Volumes[0].State) == state {
			return true, nil
		}

		return false, nil
	}, task.GetTimeout(constants.WaitTaskTimeout), constants.WaitTaskInterval)
	if err != nil {
		logger.Error(ctx, "Wait %s volume [%s] status become to [%s] failed: %+v", MyProvider, volume.VolumeId, state, err)
		return task, err
	}

	logger.Info(ctx, "Wait %s volume [%s] status become to [%s] success", MyProvider, volume.VolumeId, state)

	return task, nil
}

func (p *ProviderHandler) WaitStopInstances(ctx context.Context, task *models.Task) (*models.Task, error) {
	return p.WaitInstanceState(ctx, task, constants.StatusStopped)
}

func (p *ProviderHandler) WaitStartInstances(ctx context.Context, task *models.Task) (*models.Task, error) {
	return p.WaitInstanceState(ctx, task, constants.StatusRunning)
}

func (p *ProviderHandler) WaitDeleteInstances(ctx context.Context, task *models.Task) (*models.Task, error) {
	return p.WaitInstanceState(ctx, task, constants.StatusTerminated)
}

func (p *ProviderHandler) WaitResizeInstances(ctx context.Context, task *models.Task) (*models.Task, error) {
	return p.WaitInstanceState(ctx, task, constants.StatusStopped)
}

func (p *ProviderHandler) WaitCreateVolumes(ctx context.Context, task *models.Task) (*models.Task, error) {
	return p.WaitVolumeState(ctx, task, constants.StatusAvailable)
}

func (p *ProviderHandler) WaitAttachVolumes(ctx context.Context, task *models.Task) (*models.Task, error) {
	return p.WaitVolumeState(ctx, task, constants.StatusInUse)
}

func (p *ProviderHandler) WaitDetachVolumes(ctx context.Context, task *models.Task) (*models.Task, error) {
	return p.WaitVolumeState(ctx, task, constants.StatusAvailable)
}

func (p *ProviderHandler) WaitDeleteVolumes(ctx context.Context, task *models.Task) (*models.Task, error) {
	if task.Directive == "" {
		logger.Warn(ctx, "Skip task without directive")
		return task, nil
	}
	volume, err := models.NewVolume(task.Directive)
	if err != nil {
		return task, err
	}
	if volume.VolumeId == "" {
		logger.Warn(ctx, "Skip task without volume id")
		return task, nil
	}
	instanceService, err := p.initInstanceService(ctx, volume.RuntimeId)
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return task, err
	}

	describeOutput, err := instanceService.DescribeVolumes(
		&ec2.DescribeVolumesInput{
			VolumeIds: aws.StringSlice([]string{volume.VolumeId}),
		})
	if err != nil {
		if strings.Contains(err.Error(), "not exist") {
			logger.Warn(ctx, "Wait delete volume failed, %+v", err)
			return task, nil
		}
		logger.Error(ctx, "Send DescribeVolumes to %s failed: %+v", MyProvider, err)
		return task, err
	}

	if len(describeOutput.Volumes) == 0 {
		logger.Warn(ctx, "Volume with id [%s] not exist", volume.VolumeId)
		return task, nil
	}

	input2 := ec2.DescribeVolumesInput{
		VolumeIds: []*string{aws.String(volume.VolumeId)},
	}
	return task, instanceService.WaitUntilVolumeDeleted(&input2)
}

func (p *ProviderHandler) WaitResizeVolumes(ctx context.Context, task *models.Task) (*models.Task, error) {
	return p.WaitVolumeState(ctx, task, constants.StatusAvailable)
}

func (p *ProviderHandler) DescribeSubnets(ctx context.Context, req *pb.DescribeSubnetsRequest) (*pb.DescribeSubnetsResponse, error) {
	instanceService, err := p.initInstanceService(ctx, req.GetRuntimeId().GetValue())
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return nil, err
	}

	//filter := ec2.Filter{
	//	Name:   aws.String("availabilityZone"),
	//	Values: aws.StringSlice(req.GetZone()),
	//}

	input := new(ec2.DescribeSubnetsInput)
	if len(req.GetSubnetId()) > 0 {
		input.SubnetIds = aws.StringSlice(req.GetSubnetId())
		//input.Filters = []*ec2.Filter{&filter}
	}

	output, err := instanceService.DescribeSubnets(input)
	if err != nil {
		logger.Error(ctx, "DescribeSubnets to %s failed: %+v", MyProvider, err)
		return nil, err
	}

	if len(output.Subnets) == 0 {
		logger.Error(ctx, "Send DescribeVxNets to %s failed with 0 output subnets", MyProvider)
		return nil, fmt.Errorf("send DescribeVxNets to %s failed with 0 output subnets", MyProvider)
	}

	response := new(pb.DescribeSubnetsResponse)

	for _, sn := range output.Subnets {

		name := ""
		for _, tag := range sn.Tags {
			if aws.StringValue(tag.Key) == "Name" {
				name = aws.StringValue(tag.Value)
			}
		}

		subnet := &pb.Subnet{
			SubnetId: pbutil.ToProtoString(aws.StringValue(sn.SubnetId)),
			Name:     pbutil.ToProtoString(name),
			VpcId:    pbutil.ToProtoString(aws.StringValue(sn.VpcId)),
			Zone:     pbutil.ToProtoString(aws.StringValue(sn.AvailabilityZone)),
		}
		response.SubnetSet = append(response.SubnetSet, subnet)
	}

	response.TotalCount = uint32(len(response.SubnetSet))

	return response, nil
}

func (p *ProviderHandler) CheckResourceQuotas(ctx context.Context, clusterWrapper *models.ClusterWrapper) error {
	roleCount := make(map[string]int)
	for _, clusterNode := range clusterWrapper.ClusterNodesWithKeyPairs {
		role := clusterNode.Role
		_, isExist := roleCount[role]
		if isExist {
			roleCount[role] = roleCount[role] + 1
		} else {
			roleCount[role] = 1
		}
	}

	return nil
}

func (p *ProviderHandler) DescribeVpc(ctx context.Context, runtimeId, vpcId string) (*models.Vpc, error) {
	instanceService, err := p.initInstanceService(ctx, runtimeId)
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return nil, err
	}

	output, err := instanceService.DescribeVpcs(
		&ec2.DescribeVpcsInput{
			VpcIds: aws.StringSlice([]string{vpcId}),
		})
	if err != nil {
		logger.Error(ctx, "DescribeVpcs to %s failed: %+v", MyProvider, err)
		return nil, err
	}

	if len(output.Vpcs) == 0 {
		logger.Error(ctx, "Send DescribeVpcs to %s failed with 0 output instances", MyProvider)
		return nil, fmt.Errorf("send DescribeVpcs to %s failed with 0 output instances", MyProvider)
	}

	vpc := output.Vpcs[0]

	filter := &ec2.Filter{
		Name:   aws.String("vpc-id"),
		Values: []*string{vpc.VpcId},
	}

	subnetOutput, err := instanceService.DescribeSubnets(
		&ec2.DescribeSubnetsInput{
			Filters: []*ec2.Filter{filter},
		})
	if err != nil {
		logger.Error(ctx, "DescribeSubnets to %s failed: %+v", MyProvider, err)
		return nil, err
	}

	var subnets []string
	for _, subnet := range subnetOutput.Subnets {
		subnets = append(subnets, aws.StringValue(subnet.SubnetId))
	}

	name := ""
	for _, tag := range vpc.Tags {
		if aws.StringValue(tag.Key) == "Name" {
			name = aws.StringValue(tag.Value)
		}
	}

	return &models.Vpc{
		VpcId:   aws.StringValue(vpc.VpcId),
		Name:    name,
		Status:  aws.StringValue(vpc.State),
		Subnets: subnets,
	}, nil
}

func (p *ProviderHandler) DescribeZones(ctx context.Context, url, credential string) ([]string, error) {
	zone := DefaultZone
	awsSession, err := p.initAWSSession(ctx, url, credential, zone)
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return nil, err
	}

	var instanceService ec2iface.EC2API
	instanceService = ec2.New(awsSession)

	input := ec2.DescribeRegionsInput{}

	output, err := instanceService.DescribeRegions(&input)
	if err != nil {
		logger.Error(ctx, "DescribeRegions to %s failed: %+v", MyProvider, err)
		return nil, err
	}

	var zones []string
	for _, zone := range output.Regions {
		zones = append(zones, aws.StringValue(zone.RegionName))
	}
	return zones, nil
}

func (p *ProviderHandler) DescribeKeyPairs(ctx context.Context, url, credential, zone string) ([]string, error) {
	awsSession, err := p.initAWSSession(ctx, url, credential, zone)
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return nil, err
	}

	var instanceService ec2iface.EC2API
	instanceService = ec2.New(awsSession)

	input := ec2.DescribeKeyPairsInput{}

	output, err := instanceService.DescribeKeyPairs(&input)
	if err != nil {
		logger.Error(ctx, "DescribeKeyPairs to %s failed: %+v", MyProvider, err)
		return nil, err
	}

	var keys []string
	for _, key := range output.KeyPairs {
		keys = append(keys, aws.StringValue(key.KeyName))
	}
	return keys, nil
}

func (p *ProviderHandler) DescribeImage(ctx context.Context, runtimeId, imageName string) (string, error) {
	instanceService, err := p.initInstanceService(ctx, runtimeId)
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return "", err
	}

	filter := &ec2.Filter{Name: aws.String("name"), Values: aws.StringSlice([]string{imageName})}

	input := ec2.DescribeImagesInput{
		Filters: []*ec2.Filter{filter},
	}

	output, err := instanceService.DescribeImages(&input)
	if err != nil {
		logger.Error(ctx, "DescribeImages to %s failed: %+v", MyProvider, err)
		return "", err
	}

	if len(output.Images) == 0 {
		return "", fmt.Errorf("image with name [%s] not exist", imageName)
	}

	imageId := aws.StringValue(output.Images[0].ImageId)

	return imageId, nil
}

func (p *ProviderHandler) DescribeAvailabilityZoneBySubnetId(ctx context.Context, runtimeId, subnetId string) (string, error) {
	instanceService, err := p.initInstanceService(ctx, runtimeId)
	if err != nil {
		logger.Error(ctx, "Init %s api service failed: %+v", MyProvider, err)
		return "", err
	}

	input := ec2.DescribeSubnetsInput{
		SubnetIds: aws.StringSlice([]string{subnetId}),
	}

	output, err := instanceService.DescribeSubnets(&input)
	if err != nil {
		logger.Error(ctx, "DescribeSubnets to %s failed: %+v", MyProvider, err)
		return "", err
	}

	if len(output.Subnets) == 0 {
		return "", fmt.Errorf("subnet with id [%s] not exist", subnetId)
	}

	zone := aws.StringValue(output.Subnets[0].AvailabilityZone)

	return zone, nil
}

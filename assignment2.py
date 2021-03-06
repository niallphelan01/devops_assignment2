import logging  # Logging functionality
from os import truncate

import boto3  # import the boto api
import subprocess
import time  # pausing the interface
from tinydb import TinyDB, Query, where
#import s3_check_create  # seperate python file to check for s3 bucket
import sys  # this allows you to use the sys.exit command to quit/logout of the application
from datetime import datetime, timedelta


# Menu for new webserver
db = TinyDB('db.json')
# Global declaration of ec2 and cloudwatch
cloudwatch = boto3.resource('cloudwatch')
ec2 = boto3.resource('ec2')
ec2Client = boto3.client('ec2')
filename='log/aws_assignment.log'
# Configuration for the logfile https://docs.python.org/3/howto/logging.html + https://www.pylenin.com/blogs/python-logging-guide/
logger_format= "%(asctime)s::%(levelname)s::%(name)s::"\
             "%(filename)s::%(lineno)d::%(message)s"
logging.basicConfig(
    filename= filename,
    level=logging.DEBUG,
    format = logger_format,
    datefmt='%d/%m/%Y %I:%M:%S %p'
)
def main():    #Main function to call the main menu
    logging.info('Program started')
    menu()
def menu():
    logging.info('Main menu selected')
    print("\n\n\n              ************MAIN MENU**************")

    time.sleep(0.02)
    print()

    choice = input("""
                      A: Instance Menu
                      B: Monitoring menu
                      C: Open Logfile for information
                      D: VPC menu
                      -------------------
                      Q: Quit/Log Out

                      Please enter your choice: """)

    if choice == "A" or choice == "a":
        instance_menu()
    elif choice == "B" or choice == "b":
        monitor_menu()
    elif choice == "C" or choice == "c":
        open_logfile()
    elif choice == "D" or choice == "d":
            vpc_menu()

    elif choice == "Q" or choice == "q":
        logging.info("Exiting of program")
        sys.exit()
    else:
        print("You must only select either A,B,C, or D.")
        print("Please try again")
        menu()

def createNewInstance():
    ec2 = boto3.resource('ec2')
    print("\nStarting instance creation process, please be patient")
    try:
        TAG_SPEC = [
        {
        "ResourceType":"instance",
        "Tags": [
                {
                    "Key": "Name",
                    "Value": "BastionServer"
                }
            ]
        }
        ]
        NET_SPEC = [
            {
                "AssociatePublicIpAddress": "True"
            }
        ]
        instance = ec2.create_instances(
            ImageId='ami-099a8245f5daa82bf',  # Default instance
            MinCount=1,
            MaxCount=1,
            InstanceType='t2.nano',  # t2 nano default or micro depending upon selection
            KeyName='kp20201',
            TagSpecifications = TAG_SPEC,
            SecurityGroupIds=['sg-0f20389f889bed0a3'],  # one of my security groups that has http and ssh
            SubnetId = 'subnet-06a71d27240482424', #Launch into the public subnet
            #NetworkInterfaces = NET_SPEC
        )
        print("Instance ID:" + instance[0].id + " being created. Please be patient!")
    except:
        logging.error("Couldn't create an instance")
        print("Couldn't create an instance")
        input("\nPress Enter to continue...")
        instance_menu()
    # instance created but no tags inserted.
    try:
        instance[0].wait_until_running()
        print("Instance running")
    except:
        print("Cannot check for instanance running")
        logging.warning("Unable to check for instance running")
    try:
        print("Instance running: " + instance[0].id)
    except:
        logging.warning("No instance running on the system due to errors")
        print("No instance running")
    input("\nPress Enter to continue...")
    instance_menu()
def createNewInstanceDbServer():
    ec2 = boto3.resource('ec2')
    print("\nStarting instance creation process, please be patient")
    try:
        TAG_SPEC = [
        {
        "ResourceType":"instance",
        "Tags": [
                {
                    "Key": "Name",
                    "Value": "dbServer"
                }
            ]
        }
        ]
        NET_SPEC = [
            {
                "AssociatePublicIpAddress": "True"
            }
        ]
        instance = ec2.create_instances(
            ImageId='ami-000f250cb403819f1',  # Default instance
            MinCount=1,
            MaxCount=1,
            InstanceType='t2.nano',  # t2 nano default or micro depending upon selection
            KeyName='kp20201',
            TagSpecifications = TAG_SPEC,
            SecurityGroupIds=['sg-0d215f7e40740063a'],  # one of my security groups that has http and ssh
            SubnetId = 'subnet-0113caae4b929264e', #Launch into the private subnet
            PrivateIpAddress = '20.0.4.86',
            UserData = '#!/bin/bash su \'mongod -dbpath /home/ec2-user/db --bind_ip_all \''
         )
        print("Instance ID:" + instance[0].id + " being created. Please be patient!")
    except Exception as e:
        print(e)
        logging.error("Couldn't create an instance")
        print("Couldn't create an instance")
        input("\nPress Enter to continue...")
        instance_menu()
    # instance created but no tags inserted.
    try:
        instance[0].wait_until_running()
        print("Instance running")
    except:
        print("Cannot check for instanance running")
        logging.warning("Unable to check for instance running")
    try:
        print("Instance running: " + instance[0].id)
    except:
        logging.warning("No instance running on the system due to errors")
        print("No instance running")


    input("\nPress Enter to continue...")
    instance_menu()
def list_all_instance():  # Listing of all instances in all statuses
    ec2 = boto3.resource('ec2')
    print("\nAttempting to list instances, please be patient")
    try:
        instance_list = []
        for instance in ec2.instances.all():
            print(instance.id, instance.state, instance.public_ip_address, instance.tags)
            instance_list.append(instance)
        logging.warning("Instance list created without issue")
    except:
        logging.warning("Couldn't create a list of instances")
        print("Error handling instances more than likely due to connection")
    input("\nPress Enter to continue...")
    instance_menu()
def instance_menu():
    logging.info('Instance Menu Selected')
    print("\n\n\n              ************INSTANCE MENU**************")
    time.sleep(0.02)
    print()

    choice = input("""
                      A: Create a new Bastion Instance (in development)
                      B: List all instances (any state)
                      C: Create a new dbServer instance (in development
                    -----------------------------------------------
                      D: Terminate instance
                    -----------------------------------------------
                    -----------------------------------------------
                      Q: Back to Main Menu

                      Please enter your choice: """)

    if choice == "A" or choice == "a":
        logging.info('Create new instance selected')
        instance_menu()
        #createNewInstance()
    elif choice == "B" or choice == "b":
        list_all_instance()   #list all instances - different function to show all statuses
    elif choice == "C" or choice == "c":
        instance_menu()
        #createNewInstanceDbServer()   #create a dbServer instance
    elif choice == "D" or choice == "d":
        quitInstance()
    elif choice == "E" or choice == "e":
        instance_menu()
    elif choice == "Q" or choice == "q":
        menu()
    else:
        print("You must only select either A,B,C, or D.")
        print("Please try again")
        instance_menu()

def vpc_menu():
    logging.info('VPC Menu Selected')
    print("\n\n\n              ************Automated Systems**************")
    time.sleep(0.02)
    print()

    choice = input("""
                      A: Create an automated system *Assignment 2 setup
                      B:
                      C:
                    -----------------------------------------------
                      D: Delete and automated setups 
                    -----------------------------------------------
                      E: List all vpc's
                    -----------------------------------------------
                      Q: Back to Main Menu

                      Please enter your choice:
                      """)
    if choice == "A" or choice == "a":
        logging.info('Create new VPC selected')
        new_vpc()
    elif choice == "D" or choice == "d":
        logging.info("Delete automated setup")
        deleteautomated()
    elif choice == "E" or choice == "e":
        listvpcs()
    elif choice == "Q" or choice == "q":
        menu()
    else:
        print("You must only select either A,B,C, or D.")
        print("Please try again")
        vpc_menu()
def listvpcs():

    fltr1 = [{'Name': 'tag:Name','Values':['Assignment 2 Boto3']}]
    #vpclist=list(ec2.vpcs.filter(Filters=fltr))
    vpclist = list(ec2.vpcs.filter())
    #print(vpclist[0].id)
    print(vpclist)
    for i in vpclist:
        vpc_list = ec2Client.describe_vpcs(
            VpcIds=[
                i.id,
            ],
        )
        print(vpc_list)
    choice = input("\nPress Enter to continue...")
    vpc_menu()
def deleteautomated():
    print("This needs to be created, note that it will go through any setups in the db and then check for live systems \n and delete as required")
    #Todo: create deleteautomated script by checking for a live system
def new_vpc():
    print("This creates an automated setup")
    ec2 = boto3.resource('ec2')
    vpc = ec2.create_vpc(CidrBlock='20.0.0.0/16')
    print("VPC has been created: ")
    print(vpc)
    vpc.create_tags(Tags=[{"Key": "Name", "Value": "Assignment 2 Boto3"}])
    vpc.wait_until_available()

    ec2Client.modify_vpc_attribute( VpcId = vpc.id , EnableDnsSupport = { 'Value': True } )
    ec2Client.modify_vpc_attribute( VpcId = vpc.id , EnableDnsHostnames = { 'Value': True } )
    # create an internet gateway and attach it to VPC
    internetgateway = ec2.create_internet_gateway()
    print("Internet gateway setup: ")
    print(internetgateway)
    #db.insert({'VPC_ID': vpc.id,'IGW_ID':internetgateway.id})
    #print(db.all())
    igw_tag = internetgateway.create_tags(Tags=[{"Key": "Name", "Value": "Assignment 2 Boto3"}])
    vpc.attach_internet_gateway(InternetGatewayId=internetgateway.id)
    print("Internet gateway attached to the vpc")
    # create a route table and a public route
    routetable = vpc.create_route_table()
    route = routetable.create_route(DestinationCidrBlock='0.0.0.0/0', GatewayId=internetgateway.id)
    print("route table completed")
    print(route)
    route_tags = routetable.create_tags(Tags=[{"Key": "Name", "Value": "Assignment 2 Boto3"}])
    # create subnet and associate it with route table
    subnet = ec2.create_subnet(CidrBlock='20.0.1.0/24', VpcId=vpc.id, AvailabilityZone='eu-west-1a')
    subnet.create_tags(
        Tags=[
            {
                'Key': 'Name',
                'Value': 'Public Subnet 1a'
            },
        ]
    )

    routetable.associate_with_subnet(SubnetId=subnet.id)
    print("Public subnet 1a created ")
    print(subnet)
    subnet2 = ec2.create_subnet(CidrBlock='20.0.2.0/24', VpcId=vpc.id, AvailabilityZone='eu-west-1b')
    subnet2.create_tags(
            Tags=[
                {
                    'Key': 'Name',
                    'Value': 'Public Subnet 1b'
                },
            ]
    )
    print("Public subnet 1b created ")
    print(subnet2)
    routetable.associate_with_subnet(SubnetId=subnet2.id)
    subnet3 = ec2.create_subnet(CidrBlock='20.0.3.0/24', VpcId=vpc.id, AvailabilityZone='eu-west-1c')
    subnet3.create_tags(
            Tags=[
                {
                    'Key': 'Name',
                    'Value': 'Public Subnet 1c'
                },
            ]
    )
    print("Public subnet 1c created ")
    print(subnet3)
    routetable.associate_with_subnet(SubnetId=subnet3.id)

    #db.insert({'VPC_ID': vpc.id,'IGW_ID':internetgateway.id,"route_table_public":routetable.id, "subnet1_id":subnet.id, "subnet2_id":subnet2.id, "subnet3_id":subnet3.id})
    #print(db.all())
    #time.sleep(15)


    # Create a security group and allow SSH inbound rule through the VPC
    securitygroup1 = ec2.create_security_group(GroupName='webserver', Description='webserverSG', VpcId=vpc.id)
    securitygroup1.authorize_ingress(CidrIp='81.24.248.5/32', IpProtocol='tcp', FromPort=22, ToPort=22)
    print("Security Group webserver created, ID =")
    print(securitygroup1.id)
    # Create a security group and allow SSH inbound rule through the VPC
    securitygroup2 = ec2.create_security_group(GroupName='bastion', Description='bastionSG', VpcId=vpc.id)
    securitygroup2.authorize_ingress(CidrIp='81.24.248.5/32', IpProtocol='tcp', FromPort=22, ToPort=22)
    print("Security Group bastion created, ID =")
    print(securitygroup2.id)
    # Create a security group and allow SSH from bastion to dbServer
    securitygroup3 = ec2.create_security_group(GroupName='dbserver', Description='dbServerSG', VpcId=vpc.id)
    print("Security Group dbserver created id:")
    print(securitygroup3)

    #Assignment of ports for communication to the dbServer
    ec2Client.authorize_security_group_ingress(GroupId=securitygroup3.id,
                                                   IpPermissions=[
                                                       {
                                                           'FromPort': 22,
                                                           'IpProtocol': 'tcp',
                                                           'ToPort': 22,
                                                           'UserIdGroupPairs': [
                                                               {
                                                                   'Description': 'SSH access from the bastion server',
                                                                   'GroupId': securitygroup2.id,
                                                               },
                                                           ],
                                                       },
                                                   ],
                                               )
    #Assignment of ports for communication to the dbServer
    ec2Client.authorize_security_group_ingress(GroupId=securitygroup3.id,
                                                       IpPermissions=[
                                                           {
                                                               'FromPort': 27017,
                                                               'IpProtocol': 'tcp',
                                                               'ToPort': 27017,
                                                               'UserIdGroupPairs': [
                                                                   {
                                                                       'Description': 'MongoDB Access from webserver',
                                                                       'GroupId': securitygroup1.id,
                                                                   },
                                                               ],
                                                           },
                                                       ],
                                                   )
    #create rule allowing for incoming traffic to the webserver from the loadbalancer
    securitygroup_lb = ec2.create_security_group(GroupName='loadbalancer', Description='loadbalancerSG', VpcId=vpc.id)
    securitygroup_lb.authorize_ingress(CidrIp='0.0.0.0/0', IpProtocol='tcp', FromPort=80, ToPort=80)
    securitygroup_lb.authorize_ingress(CidrIp='0.0.0.0/0', IpProtocol='tcp', FromPort=443, ToPort=443)
    print("Security Group loadbalancer created, ID = ")
    print(securitygroup_lb.id)
    #create rule allowing for incoming traffic to the webserver from the loadbalancer
    ec2Client.authorize_security_group_ingress(GroupId=securitygroup1.id,
                                                       IpPermissions=[
                                                           {
                                                               'FromPort': 3000,
                                                               'IpProtocol': 'tcp',
                                                               'ToPort': 3000,
                                                               'UserIdGroupPairs': [
                                                                   {
                                                                       'Description': 'Port 3000 Traffic from the loadbalancer',
                                                                       'GroupId': securitygroup_lb.id,
                                                                   },
                                                               ],
                                                           },
                                                       ],
                                                   )

    #Allocate an Elastic IP address
    eip = ec2Client.allocate_address(
    Domain='vpc',
    )
    time.sleep(2)
    eipAllocationId=eip['AllocationId']
    print("Elastic IP created: ")
    print(eip)
    time.sleep(5)
    #Create a NAT gateway
    nat = ec2Client.create_nat_gateway(
        AllocationId=eipAllocationId,
        SubnetId= subnet.id,
    )
    print("The details of the nat are the following: ")
    print(nat)
    waiter = ec2Client.get_waiter('nat_gateway_available')
    #Todo check for this waiter functionality
    natGatewayId = nat['NatGateway']['NatGatewayId']
    print("The NatGatewayId is")
    print(nat)
    print("Please wait while the NAT is being created")
    time.sleep(20)
    # create a route table and a private route
    private_routetable = vpc.create_route_table()
    route = private_routetable.create_route(DestinationCidrBlock='0.0.0.0/0', NatGatewayId=natGatewayId)
    print("The route has been created for the private subnet")
    print(route)
    route_tags = private_routetable.create_tags(Tags=[{"Key": "Name", "Value": "NAT Assignment 2 Boto3"}])
    subnet_private = ec2.create_subnet(CidrBlock='20.0.4.0/24', VpcId=vpc.id, AvailabilityZone='eu-west-1a')
    time.sleep(1)
    subnet_private.create_tags(
                Tags=[
                    {
                        'Key': 'Name',
                        'Value': 'Private Subnet 1a'
                    },
                ]
        )
    print("Private subnet created")
    print(subnet_private)
    private_routetable.associate_with_subnet(SubnetId=subnet_private.id)
    # adding the creation of the db instance to the automated script
    time.sleep(10)
    ec2 = boto3.resource('ec2')
    print("\nStarting instance creation process, please be patient")
    try:
        TAG_SPEC = [
            {
                "ResourceType": "instance",
                "Tags": [
                    {
                        "Key": "Name",
                        "Value": "dbServer"
                    }
                ]
            }
        ]
        NET_SPEC = [
            {
                "AssociatePublicIpAddress": "True"
            }
        ]
        userdata = """#!/bin/bash
                   nohup mongod -dbpath /home/ec2-user/db --bind_ip_all
        """
        instance = ec2.create_instances(
            ImageId='ami-00478fab923418f90',  # Db instance
            MinCount=1,
            MaxCount=1,
            InstanceType='t2.nano',  # t2 nano default or micro depending upon selection
            KeyName='kp20201',
            TagSpecifications=TAG_SPEC,
            SecurityGroupIds=[securitygroup3.id,],  # one of my security groups that has http and ssh
            SubnetId=subnet_private.id,  # Launch into the private subnet
            PrivateIpAddress='20.0.4.86',
           # UserData=userdata
           # Note that mongod is setup to auto run on this AMI instance [sudo systemctl enable mongod]
        )
        print("Instance ID:" + instance[0].id + " being created. Please be patient!")
    except Exception as e:
        print(e)
        logging.error("Couldn't create an instance")
        print("Couldn't create an instance")
        input("\nPress Enter to continue...")
        instance_menu()
    #https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/elbv2.html
    elb = boto3.client('elbv2')
    #create the target group
    tg = elb.create_target_group(
        Name='Assignment2-boto3-tg',
        Port=3000,
        Protocol='HTTP',
        VpcId=vpc.id,
    )
    print("Rarget group details: ")
    print(tg)
    targetgroup_arn= tg['TargetGroups'][0]['TargetGroupArn']
    #Create the loadbalancer
    elb_info = elb.create_load_balancer(
        Name='Boto3-load-balancer',
        Scheme='internet-facing',
        Subnets=[
            subnet.id,
            subnet2.id,
            subnet3.id,
        ],
        SecurityGroups= [
                        securitygroup_lb.id,
        ],
        Type= 'application',
    )
    print("Load balancer information: ")
    print(elb)
    elb_arn= elb_info['LoadBalancers'][0]['LoadBalancerArn']
    #Create the listner on the LB
    elb_listner1 = elb.create_listener(
        DefaultActions=[
            {
                'TargetGroupArn': targetgroup_arn,
                'Type': 'forward',
            },
        ],
        LoadBalancerArn=elb_arn,
        Port=80,
        Protocol='HTTP',
    )
    print("The listner for the elb is the following: ")
    print(elb_listner1)
    elb_listner2 = elb.create_listener(
        Certificates=[
            {
                'CertificateArn': 'arn:aws:acm:eu-west-1:013355473762:certificate/6da9509f-05ad-47a1-96c9-98dc9bf8a4a4',
            },
        ],
        DefaultActions=[
            {
                'TargetGroupArn': targetgroup_arn,
                'Type': 'forward',
            },
        ],
        LoadBalancerArn=elb_arn,
        Port=443,
        Protocol='HTTPS',
        SslPolicy='ELBSecurityPolicy-2016-08',
    )
    print("The listner for the elb is the following: ")
    print(elb_listner1)

    db.insert(
                     {
                     'VPC_ID': vpc.id,
                     'IGW_ID':internetgateway.id,
                     'route_table_public':routetable.id,
                     'subnet1_id':subnet.id, 'subnet2_id':subnet2.id, 'subnet3_id':subnet3.id,
                     'securitygroup1':securitygroup1.id, 'securitygroup2':securitygroup2.id, 'securitygroup3':securitygroup3.id, 'securitygrouplb':securitygroup_lb.id, 'subnetprivate_id': subnet_private.id,
                     'EipAllocation_id': eipAllocationId,
                     'NatGatewayId': natGatewayId,
                     'private_routetable': private_routetable.id,
                     'targetgroup_arn': targetgroup_arn,
                     'elb_arn':elb_arn,
                     }
                   )
    test = db.all()
    #print("VPC_ID" +test[0]['VPC_ID'])

    #low level client representing Auto Scaling
    ec2auto = boto3.client('autoscaling')
    userdatalc = """#!/bin/bash
                  su -ec2user -c 'cd /home/ec2-user/donation-web-10/
                  node index.js'"""
    lc = ec2auto.create_launch_configuration(
            ImageId='ami-0e3bad3ef579c546e',
            InstanceType='t2.nano',
            LaunchConfigurationName='Boto3AssignmentLC',
            SecurityGroups=[
               securitygroup1.id,
            ],
            UserData = userdatalc,
            InstanceMonitoring={'Enabled':True},
            AssociatePublicIpAddress=True,
    )
    print("This is the LC:")
    print(lc)
    asgsubnets= subnet.id +","+subnet2.id+","+subnet3.id
    time.sleep(20)
    asg = ec2auto.create_auto_scaling_group(
            AutoScalingGroupName='Boto3AssignmentASG',
            LaunchConfigurationName='Boto3AssignmentLC',
            AvailabilityZones=[
                    'eu-west-1a','eu-west-1b','eu-west-1c'
                ],
            MaxSize=3,
            MinSize=1,
            HealthCheckType='EC2',
            VPCZoneIdentifier= asgsubnets,
            Tags=[
                    {
                        'ResourceId': 'Boto3AssignmentASG',
                        'ResourceType': 'auto-scaling-group',
                        'Key': 'Name',
                        'Value': 'Boto3AssignmentASG',
                        'PropagateAtLaunch': True,
                    },
                ],
        )
    print("asg printout: ")
    print(asg)
    response = ec2auto.attach_load_balancer_target_groups(
         AutoScalingGroupName='Boto3AssignmentASG',
         TargetGroupARNs=[
             targetgroup_arn,
         ]
    )
    print(response)

    #ami-03778245a5d9f1082

    #print(test.elb_arn)
            #print(db.all())
            #time.sleep(15)
    print("------Take notice------------")
    print("*******")
    print("Create a homemade bastion server for connection with dbserver using the bastionsg and public ip")
    print("*******")
    print("-----------------------------")
    choice = input("\nPress Enter to continue...")

    # TODO: add the asg and lc details to the db information
    # TODO: add try/except to the creation of all the items e.g. vpc etc
    # TODO: create dbserver that will run up from ami instance
    # TODO: create a new AMI for webserver instance with a static internal ip for the dbserver
    # TODO: Add details to the logger of creation of vpc...or errors

    vpc_menu()

def monitor_menu():
    print("\n\n\n              ************MONITORING MENU**************")
    time.sleep(0.02)
    print()

    choice = input("""
                      A: Monitor the CPU utilisation on an instance
                      B: Set Alarm on instance (note NetworkIn less than 30k)
                      ------------------------
                      C: Set custom monitoring on EC2 instance to cloudwatch
                      D: Get custom data back from EC2 instance 
                      ------------------------ 
                      E: Search for all monitored instances for CPU utilisation
                      F: Search for current monitored instances for CPU utilisation
                      Q: Back to Main Menu

                      Please enter your choice: """)

    if choice == "A" or choice == "a":
        select_monitor()
    elif choice == "B" or choice == "b":
        cloudwatch_alarm()
    elif choice == "C" or choice == "c":
        pushmonitoring()
    elif choice == "D" or choice == "d":
        custom_monitoring()
    elif choice == "E" or choice == "e":
        monitor_db()
    elif choice == "F" or choice == "f":
        monitor_specific_db()
    elif choice == "Q" or choice == "q":
        menu()
    else:
        print("You must only select either A,B,C, or D.")
        print("Please try again")
        monitor_menu()
def monitor_db():
    InstanceMonitored = Query()
    print(db.search(InstanceMonitored.AverageutilisationPercentage.exists()))
    input("\nPress Enter to continue...")
    monitor_menu()
def monitor_specific_db():
    instance_list = []
    try:
        instance_list = instance_listing(
            ['running'])  # function that takes in the instance status and returns an arrany of instance id's
    except:
        logging.warning("Couldn't create a list of instances")
        print("Error searching for instances:")
    if not instance_list:  # check for an empty array i.e. no running instances
        print("No running instances")
        logging.info("No running instances")
        monitor_menu()
    else:
        choice = input("""Please select the running instance to view CPU utilisation:""")

        try:
            selectedinstance = instance_list[int(choice)]
            InstanceMonitored = Query()
            result = db.search(InstanceMonitored.InstanceMonitored == selectedinstance.id)
            if not result:
                print("No results for this instance")
            else:
                for i in result:
                   print(i)
            input("\nPress Enter to continue...")
            monitor_menu()
        except Exception as e:
            print(e)
            logging.warning("Issue with choice entry as no data yet for the instance")

def select_monitor():
    instance_list = []
    try:
        instance_list = instance_listing(['running'])   #function that takes in the instance status and returns an arrany of instance id's
    except:
        logging.warning("Couldn't create a list of instances")
        print("Error searching for instances:")
    if not instance_list:  # check for an empty array i.e. no running instances
        print("No running instances")
        logging.info("No running instances")
        monitor_menu()
    else:
        choice = input("""Please select the instance number to monitor:""")

        try:
            selectedinstance = instance_list[int(choice)]
            selectedinstance.monitor()

            metric_iterator = cloudwatch.metrics.filter(Namespace='AWS/EC2',
                                                        MetricName='CPUUtilization',
                                                        Dimensions=[{'Name':'InstanceId', 'Value': selectedinstance.id}])
            metric = list(metric_iterator)[0]    # extract first (only) element
            print(metric_iterator)
            response = metric.get_statistics(StartTime = datetime.utcnow() - timedelta(minutes=5),   # 5 minutes ago
                                             EndTime=datetime.utcnow(),                              # now
                                             Period=300,                                             # 5 min intervals
                                             Statistics=['Average'])
            print("Average CPU utilisation:", response['Datapoints'][0]['Average'], response['Datapoints'][0]['Unit'])
            avg = response['Datapoints'][0]['Average']
            db.insert({'InstanceMonitored': selectedinstance.id,'AverageutilisationPercentage':avg, 'Date_time':datetime.now().strftime('%Y-%m-%d %H:%M:%S')})
            input("\nPress Enter to continue...")
            if choice == "R" or choice == "r":
                select_monitor()
            else:
               monitor_menu()
        except Exception as e:
            print(e)
            logging.warning("Issue with choice entry as no data yet for the instance")
            print("Issue with choice entry as no data yet for the instance")
            choice = input("\nPress Enter to continue...or R to repeat")
            if choice == "R" or choice == "r":
                select_monitor()
            else:
               monitor_menu()
def instance_listing(status):
    i = 0
    instance_list = []
    filters = [
        {
            'Name': 'instance-state-name',
            'Values': status
        }
    ]
    logging.info("Attempting to create a list of instances")

    try:

        for instance in ec2.instances.filter(Filters=filters):
            instance_list.append(instance)
            try:
                for tag in instance.tags:  # As AWS stores tags as key and value
                    print("[%d]" % (i) + instance.id + " Tag Key: " + tag['Key'] + " Value: " + tag['Value'])
            except:
                print("[%d]" % (i) + instance.id + " No Tags")
            logging.info(instance.id + instance.instance_type)
            i += 1
    except:
        logging.warning("Couldn't create a list of instances")
        print("Error searching for instances:")
    return instance_list
def cloudwatch_alarm():
    instance_list = []
    try:
        instance_list = instance_listing(['running'])   #function that takes in the instance status and returns an arrany of instance id's
    except:
        logging.warning("Couldn't create a list of instances")
        print("Error searching for instances:")
    if not instance_list:  # check for an empty array i.e. no running instances
        print("No running instances")
        logging.info("No running instances")
        monitor_menu()
    else:
        choice = input("""Please select the instance number to monitor:""")
        print(choice)
        try:
            selectedinstance = instance_list[int(choice)]
            selectedinstance.monitor()
            alarm_name = "Webserver_NetworkIn_instance_" + selectedinstance.id
            cloudwatch_client = boto3.client('cloudwatch')
            #https://boto3.amazonaws.com/v1/documentation/api/latest/guide/cw-example-creating-alarms.html
            response = cloudwatch_client.put_metric_alarm(
                 AlarmName= alarm_name,
                 AlarmActions=['arn:aws:sns:eu-west-1:013355473762:test'],   #this arn will send an email to my email account
                 ComparisonOperator='LessThanThreshold',
                 EvaluationPeriods=1,
                 MetricName='NetworkIn',
                 Namespace='AWS/EC2',
                 Period=60,
                 Statistic='Average',
                 Threshold=30000,
                 ActionsEnabled=True,
                 AlarmDescription='Alarm when Network In < 30k',   #very low for example for assignment
                 Dimensions=[
                     {
                     'Name': 'InstanceId',
                     'Value': selectedinstance.id
                     },
                 ],
                 Unit='None'  #important to set this correctly as leaving it to the incorrect value will cause errors displaying in cloudwatch alarms page
            )
            print(response)
            response2 = cloudwatch_client.describe_alarm_history(
                 AlarmName=alarm_name,
                 HistoryItemType='Action',
                 StartDate=datetime(2015, 1, 1),
                 EndDate=datetime(2022, 1, 1),
                 MaxRecords=55,
            )
            print(response2)
            logging.info(response2)
            input("\nPress Enter to continue...")
            monitor_menu()
        except Exception as e:
            print(e)
            logging.warning(e)
            print("Incorrect choice, please try again")
            input("\nPress Enter to continue...")
            monitor_menu()
def pushmonitoring():
    instance_list = []
    try:
        instance_list = instance_listing(['running'])
    except:
        logging.warning("Couldn't create a list of instances")
        print("Error searching for instances:")

    if not instance_list:
        logging.warning("No running instances")
        print("No running instances")
        input("\nPress Enter to continue...")
        monitor_menu()
    else:
        choice = input("""Which instance would you like to setup a server on?""")
        print(choice)
        try:
            selected_instance = instance_list[int(choice)]
            ssh_text = "ssh -o StrictHostkeyChecking=no -i kp20201.pem ec2-user@"
            selected_instance.monitor() #enabled detailed monitoring
            subprocess.run("scp -i kp20201.pem credentials ec2-user@" + selected_instance.public_ip_address + ":.",
                                   shell=True)  # scp to copy the monitoring file to the webserver
            subprocess.run("scp -i kp20201.pem config ec2-user@" + selected_instance.public_ip_address + ":.",
                                   shell=True)  # scp to copy the monitoring file to the webserver
            subprocess.run(
                ssh_text + selected_instance.public_ip_address + " \ 'mkdir ~/.aws; mv credentials ~/.aws/credentials; mv config ~/.aws/config'",
                shell=True) #move the credentials and aws config files to the required folders
            #create a file call mem.sh
            f = open("mem.sh", "w+")
            f.write("#!/bin/bash\n")
            f.write("USEDMEMORY=$(free -m | awk 'NR==2{printf \"%.2f\t\", $3*100/$2 }')\n")
            f.write("TCP_CONN=$(netstat -an | wc -l)\n")
            f.write("TCP_CONN_PORT_80=$(netstat -an | grep 80 | wc -l)\n")
            f.write("TCP_CONN_PORT_3000=$(netstat -an | grep 3000 | wc -l)\n")
            f.write("USERS=$(uptime |awk '{ print $6 }')\n")
            f.write("IO_WAIT=$(iostat | awk 'NR==4 {print $5}')\n")
            f.write("instance_id=" + selected_instance.id+"\n")
            f.write("aws cloudwatch put-metric-data --metric-name memory-usage --dimensions Instance=$instance_id  --namespace \"Custom\" --value $USEDMEMORY \n")
            f.write("aws cloudwatch put-metric-data --metric-name Tcp_connections --dimensions Instance=$instance_id  --namespace \"Custom\" --value $TCP_CONN\n")
            f.write("aws cloudwatch put-metric-data --metric-name TCP_connection_on_port_80 --dimensions Instance=$instance_id  --namespace \"Custom\" --value $TCP_CONN_PORT_80\n")
            f.write("aws cloudwatch put-metric-data --metric-name TCP_connection_on_port_3000 --dimensions Instance=$instance_id  --namespace \"Custom\" --value $TCP_CONN_PORT_3000\n")
            f.write("aws cloudwatch put-metric-data --metric-name IO_WAIT --dimensions Instance=$instance_id --namespace \"Custom\" --value $IO_WAIT\n")
            f.close()
            subprocess.run("scp -i kp20201.pem mem.sh ec2-user@" + selected_instance.public_ip_address + ":.",
                                   shell=True)  # scp to copy the monitoring file to the webserver
            subprocess.run("scp -i kp20201.pem cron.sh ec2-user@" + selected_instance.public_ip_address + ":.",
                                   shell=True)  # scp to copy the cronjob file to the webserver
            subprocess.run(
                ssh_text + selected_instance.public_ip_address + " \ 'chmod +x mem.sh; chmod +x cron.sh; ./mem.sh;sudo ./cron.sh'",
                shell=True) #change the permissions on the mem.sh and cron files and run both


            input("\nPress Enter to continue...")
            monitor_menu()
        except:
            logging.warning("Issue with choice entry to select an instance")
            print("Incorrect choice, as server may not be fully loaded,  please try again thanks")
            input("\nPress Enter to continue...")
            monitor_menu()
def custom_monitoring():
    instance_list = []
    try:
        instance_list = instance_listing(['running'])   #function that takes in the instance status and returns an arrany of instance id's
    except:
        logging.warning("Couldn't create a list of instances")
        print("Error searching for instances:")
    if not instance_list:  # check for an empty array i.e. no running instances
        print("No running instances")
        logging.info("No running instances")
        monitor_menu()
    else:
        choice = input("""Please select the instance number to monitor:""")

        try:
            selectedinstance = instance_list[int(choice)]
            selectedinstance.monitor()
            print(selectedinstance.id)
            cloudwatch_client = boto3.client('cloudwatch')
            response = cloudwatch_client.get_metric_statistics(Namespace='Custom',
                                                        MetricName='IO_WAIT',Dimensions=[{'Value': selectedinstance.id, 'Name':'Instance'}], StartTime = datetime.utcnow() - timedelta(minutes=5),   # 5 minutes ago
                                             EndTime=datetime.utcnow(),                              # now
                                             Period=300,                                             # 5 min intervals
                                             Statistics=['Average'])
            print ("Average IO wait time:", response['Datapoints'][0]['Average'], "seconds")
            response = cloudwatch_client.get_metric_statistics(Namespace='Custom',
                                                        MetricName='Tcp_connections',Dimensions=[{'Value': selectedinstance.id, 'Name':'Instance'}], StartTime = datetime.utcnow() - timedelta(minutes=5),   # 5 minutes ago
                                             EndTime=datetime.utcnow(),                              # now
                                             Period=300,                                             # 5 min intervals
                                             Statistics=['Average'])
            print ("Tcp_connections:", response['Datapoints'][0]['Average'], "connections")
            response = cloudwatch_client.get_metric_statistics(Namespace='Custom',
                                                        MetricName='TCP_connection_on_port_80',Dimensions=[{'Value': selectedinstance.id, 'Name':'Instance'}], StartTime = datetime.utcnow() - timedelta(minutes=5),   # 5 minutes ago
                                             EndTime=datetime.utcnow(),                              # now
                                             Period=300,                                             # 5 min intervals
                                             Statistics=['Average'])
            print ("Tcp_connections on port 80:", response['Datapoints'][0]['Average'], "connections")
            response = cloudwatch_client.get_metric_statistics(Namespace='Custom',
                                                        MetricName='TCP_connection_on_port_3000',Dimensions=[{'Value': selectedinstance.id, 'Name':'Instance'}], StartTime = datetime.utcnow() - timedelta(minutes=5),   # 5 minutes ago
                                             EndTime=datetime.utcnow(),                              # now
                                             Period=300,                                             # 5 min intervals
                                             Statistics=['Average'])
            print ("Tcp_connections on port 3000:", response['Datapoints'][0]['Average'], "connections")
            response = cloudwatch_client.get_metric_statistics(Namespace='Custom',
                                                        MetricName='memory-usage',Dimensions=[{'Value': selectedinstance.id, 'Name':'Instance'}], StartTime = datetime.utcnow() - timedelta(minutes=5),   # 5 minutes ago
                                             EndTime=datetime.utcnow(),                              # now
                                             Period=300,                                             # 5 min intervals
                                             Statistics=['Average'])
            print ("Memory-usage:", response['Datapoints'][0]['Average'], "percent")
            input("\nPress Enter to continue...")

            monitor_menu()
        except Exception as e:
            print(e)
            logging.warning("Issue with choice entry as incorrect setup for custom data")
            print("Issue with choice entry as incorrect setup for custom data")
            choice = input("\nPress Enter to continue...or R to repeat")
            if choice == "R" or choice == "r":
                custom_monitoring()
            else:
               monitor_menu()
def open_logfile():
    try:
        subprocess.call('nano log/aws_assignment.log', shell=True)
        input("\nPress Enter to continue...")
        main()

    except Exception as e:
        print(e)
        input("\nPress Enter to continue...")
        main()
def quitInstance():
    instance_list = []
    try:
        instance_list = instance_listing(['running'])   #function that takes in the instance status and returns an arrany of instance id's
    except:
        logging.warning("Couldn't create a list of instances")
        print("Error searching for instances:")
    if not instance_list:  # check for an empty array i.e. no running instances
        print("No running instances")
        logging.info("No running instances")
        instance_menu()
    else:
        choice = input("""Please select the instance number to terminate:""")
        try:
            selectedinstance = instance_list[
                int(choice)]  # access the object returned for the selected instance
            print("The instance to be terminated is the following: " + selectedinstance.id)
            print("Please be patient")
            logging.info("The instance to be terminated is the following: " + selectedinstance.id)
            response = selectedinstance.terminate()
            logging.info(response)
            print(response)  # Printing the instance that has been terminated
            input("\nPress Enter to continue...")
            instance_menu()
        except Exception as error:
            print(error)
            logging.warning("Issue with choice entry to terminate an instance")
            print("Incorrect choice, please try again")
            input("\nPress Enter to continue...")
            instance_menu()

main()

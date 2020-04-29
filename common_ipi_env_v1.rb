install_dir = "install-dir"
install_dir_absolute = Host.localhost.absolute_path(install_dir)
Host.localhost.mkdir(install_dir)
cluster_info_json_file = File.join(install_dir_absolute, "cluster_info.json")
if File.exist? cluster_info_json_file
  cluster_info_data = JSON.parse(File.read(cluster_info_json_file))
else
  cluster_info_data = {}
end

cloud_type = conf[:services, iaas_name, :cloud_type]
iaas = iaas_by_service(iaas_name)
ssh_key_path = nil

if (not defined?(master_hyperthreading)) || (master_hyperthreading.nil?)
  master_hyperthreading="Enabled"
end

if (not defined?(node_hyperthreading)) || (node_hyperthreading.nil?)
  node_hyperthreading="Enabled"
end

if (not defined?(master_architecture)) || (master_architecture.nil?)
  master_architecture="amd64"
end

if (not defined?(node_architecture)) || (node_architecture.nil?)
  node_architecture="amd64"
end

if (not defined?(pull_secret_file)) || (pull_secret_file.nil?)
  pull_secret_file="~/.docker/config.json"
end

if defined?(disable_worker_machineset) && disable_worker_machineset
  DISABLE_WORKER_MACHINESET = disable_worker_machineset
else
  DISABLE_WORKER_MACHINESET = "no"
end

if defined?(disable_master_machineset) && disable_master_machineset
  DISABLE_MASTER_MACHINESET = disable_master_machineset
else
  DISABLE_MASTER_MACHINESET = "no"
end

if defined?(disable_cloud_credential_operator) && disable_cloud_credential_operator
  DISABLE_CCO = disable_cloud_credential_operator
else
  DISABLE_CCO = "no"
end

if defined?(enable_realtime_kernel) && enable_realtime_kernel
  ENABLE_RT_KERNEL = enable_realtime_kernel
else
  ENABLE_RT_KERNEL = "no"
end

cluster_name = instances_name_prefix.gsub(/[-_]*$/, "").gsub(/[_]/, "-")
install_config = {
  "apiVersion" => "v1",
  "controlPlane" => {
    "architecture" => master_architecture, "hyperthreading" => master_hyperthreading, "name" => "master", "platform" => {}, "replicas" => num_masters
  },
  "compute" => [
    {"architecture" => node_architecture, "hyperthreading" => node_hyperthreading, "name" => "worker", "platform" => {}, "replicas" => num_workers},
  ],
  "metadata" => {"name" => cluster_name},
  "platform" => {
    # fill based on IaaS
  },
  # "pullSecret" => File.read(expand_path("config/credentials/image-repos-pull-secret.json")),
  "pullSecret" => File.read(File.expand_path(pull_secret_file)),
}

my_network = {
    "clusterNetwork" => [{
      "cidr" => "10.128.0.0/14",
      "hostPrefix" => 23,
    }],
    "serviceNetwork" => ["172.30.0.0/16"],
    "machineNetwork" => [{
      "cidr" => "10.0.0.0/16"
    }],
    "networkType" => (defined?(networkType) ? networkType : "OpenShiftSDN"),
}

if defined?(custom_network_file) && custom_network_file
  install_config["networking"] = YAML.load(File.read(File.expand_path("../../network_files/#{custom_network_file}", __FILE__)))
else
  install_config["networking"] = my_network
end

if defined?(publish_strategy) && publish_strategy
  install_config["publish"] = publish_strategy
  PUBLISH_STRATEGY = publish_strategy
else
  install_config["publish"] = 'External'
end

if defined?(additional_ca) && additional_ca
  install_config["additionalTrustBundle"] = File.read(File.expand_path('~/qe-additional-ca.crt'))
end

if defined?(enable_proxy) && enable_proxy && enable_proxy.to_s.downcase == "yes"
  install_config["proxy"] = {
    "httpProxy" => http_proxy,
    "httpsProxy" => https_proxy,
    "noProxy" => no_proxy
  }
end

if defined?(ssh_bastion_enable) && ssh_bastion_enable
    DEPLOY_SSH_BASTION = ssh_bastion_enable
else
    DEPLOY_SSH_BASTION = "no"
end

if defined?(deploy_ipv6_bastion) && deploy_ipv6_bastion
    DEPLOY_IPV6_BASTION = deploy_ipv6_bastion
else
    DEPLOY_IPV6_BASTION = "no"
end

if defined?(fips_enable) && fips_enable
    install_config["fips"] = fips_enable
end

if defined?(service_catalog_enable) && service_catalog_enable
    ENABLE_SERVICE_CATALOG = service_catalog_enable
else
    ENABLE_SERVICE_CATALOG = "no"
end

if defined?(use_internal_opsrc) && use_internal_opsrc
    USE_INTERNAL_OPSRC = use_internal_opsrc
else
    USE_INTERNAL_OPSRC = "no"
end

if defined?(use_stage_opsrc) && use_stage_opsrc
    USE_STAGE_OPSRC = use_stage_opsrc
else
    USE_STAGE_OPSRC = "no"
end

if defined?(install_asb_tsb) && install_asb_tsb
    INSTALL_ASB_TSB = install_asb_tsb
else
    INSTALL_ASB_TSB = "no"
end

if defined?(install_logging) && install_logging
    INSTALL_LOGGING = install_logging
else
    INSTALL_LOGGING = "no"
end

if defined?(mirror_release_image_enable) && mirror_release_image_enable && mirror_release_image_enable.to_s.downcase == "yes"
  MIRROR_RELEASE_IMAGE_ENABLE = "yes"
else
  MIRROR_RELEASE_IMAGE_ENABLE = "no"
end

base_vars = {
  "MIRROR_RELEASE_IMAGE_ENABLE" => MIRROR_RELEASE_IMAGE_ENABLE,
  "DISABLE_WORKER_MACHINESET" => DISABLE_WORKER_MACHINESET,
  "DISABLE_MASTER_MACHINESET" => DISABLE_MASTER_MACHINESET,
  "add_ingress_records_manually" => (defined?(add_ingress_records_manually) ? add_ingress_records_manually : "no"),
  "IAAS_PLATFORM" => cloud_type,
  "PUBLISH_STRATEGY" => (defined?(PUBLISH_STRATEGY) && PUBLISH_STRATEGY ? PUBLISH_STRATEGY : ""),
  "DEPLOY_SSH_BASTION" => DEPLOY_SSH_BASTION,
  "DEPLOY_IPV6_BASTION" => DEPLOY_IPV6_BASTION,
  "DISABLE_CCO" => DISABLE_CCO,
  "ENABLE_RT_KERNEL" => ENABLE_RT_KERNEL,
  "ENABLE_SERVICE_CATALOG" => ENABLE_SERVICE_CATALOG,
  "USE_INTERNAL_OPSRC" => USE_INTERNAL_OPSRC,
  "USE_STAGE_OPSRC" => USE_STAGE_OPSRC,
  "INSTALL_LOGGING" => INSTALL_LOGGING,
  "INSTALL_ASB_TSB" => INSTALL_ASB_TSB

  # "OPENSHIFT_INSTALL_EMAIL_ADDRESS" => "cucushift@redhat.com",
  # "OPENSHIFT_INSTALL_PASSWORD" => "aosqetesting",
}

if defined?(env_vars) && Hash === env_vars
  env_vars.merge!(base_vars)
  #env_vars = base_vars.merge(Collections.deep_hash_strkeys env_vars)
else
  env_vars = base_vars
end

release_image_mirror_install_file = install_dir_absolute + "/release_image_mirror.install.yaml"
if defined?(mirror_release_image_enable) && mirror_release_image_enable && mirror_release_image_enable.to_s.downcase == "yes" && File.exist?(release_image_mirror_install_file)
  install_config.merge!(YAML.load(File.read(release_image_mirror_install_file)))
end

customer_vpc_subnets_file = install_dir_absolute + "/customer_vpc_subnets.json"
if defined?(create_customer_vpc) && create_customer_vpc && create_customer_vpc.to_s.downcase == "yes" && File.exist?(customer_vpc_subnets_file)
  existing_subnets = JSON.parse(File.read(customer_vpc_subnets_file))

  cluster_proxy_setting_file = install_dir_absolute + "/cluster_proxy_setting.json"
  if defined?(enable_proxy) && enable_proxy && enable_proxy.to_s.downcase == "yes" && File.exist?(cluster_proxy_setting_file)
    install_config["proxy"] = JSON.parse(File.read(cluster_proxy_setting_file))
  end
end

case cloud_type
when "aws"
  awsprofile = "flexy-installer"
  awscreds = Tempfile.new("awscreds", Host.localhost.workdir)
  awscreds.write("[#{awsprofile}]\n" \
                 "aws_access_key_id = #{iaas.access_key}\n" \
                 "aws_secret_access_key = #{iaas.secret_key}\n")
  awscreds.close
  # keep reference of temp file until installer exit to avoid it being deleted
  proc {
    _awscreds = awscreds
    at_exit { puts "deleting #{_awscreds.path}"; _awscreds.unlink }
  }.call

  install_config["baseDomain"] = iaas.config[:install_base_domain]

  if iaas&.config&.dig(:host_opts, :ssh_private_key)
    ssh_key_path = expand_private_path(iaas.config[:host_opts][:ssh_private_key])
    install_config["sshKey"] = File.read(ssh_key_path.sub(/(?:\.pem)?$/, ".pub")).gsub(/\n$/, '')
  end
  platform_aws_opt = {
    "region" => (defined?(region) and (not region.nil?)) ? region : iaas.config[:config_opts][:region]
  }

  if defined?(bootimage_ami) && bootimage_ami
    platform_aws_opt = platform_aws_opt.merge({ "amiID" => bootimage_ami })
  end

  if defined?(existing_subnets) && existing_subnets && (existing_subnets.length > 0)
    platform_aws_opt = platform_aws_opt.merge({ "subnets" => existing_subnets })
  end

  install_config["platform"]["aws"] = platform_aws_opt

  if defined?(vm_type) && vm_type
    vm_type_masters ||= vm_type
    vm_type_workers ||= vm_type
  end

  masters_aws_opt = {}
  workers_aws_opt = {}

  if vm_type_masters
    masters_aws_opt = masters_aws_opt.merge({ "type" => vm_type_masters })
  end

  if vm_type_workers
    workers_aws_opt = workers_aws_opt.merge({ "type" => vm_type_workers })
  end

  if ! masters_aws_opt.empty?
    install_config["controlPlane"]["platform"] = {
      "aws" => masters_aws_opt
    }
  end

  if ! workers_aws_opt.empty?
    install_config["compute"][0]["platform"] = {
      "aws" => workers_aws_opt
    }
  end

  env_vars.merge!({
    "AWS_REGION" => ((defined?(region) and (not region.nil?)) ? region : iaas.config[:config_opts][:region]),
    "BASE_DOMAIN" => iaas.config[:install_base_domain],
    "AWS_PROFILE" => awsprofile,
    "AWS_SHARED_CREDENTIALS_FILE" => awscreds.path,
  }) { |key, v1, v2| v1 ? v1 : v2 }

when "gce"
  gcpcreds = Tempfile.new("gcpcreds", Host.localhost.workdir)
  gcpcreds.write(File.read(expand_private_path(iaas.config[:json_cred])))
  gcpcreds.close
  # keep reference of temp file until installer exit to avoid it being deleted
  proc {
    _gcpcreds = gcpcreds
    at_exit { puts "deleting #{_gcpcreds.path}"; _gcpcreds.unlink }
  }.call

  if defined?(baseDomain) and (not baseDomain.nil?)
      install_config["baseDomain"] = baseDomain
  else
      install_config["baseDomain"] = iaas.config[:install_base_domain]
  end

  if iaas&.config&.dig(:host_opts, :ssh_private_key)
    ssh_key_path = expand_private_path(iaas.config[:host_opts][:ssh_private_key])
    install_config["sshKey"] = File.read(ssh_key_path.sub(/(?:\.pem)?$/, ".pub")).gsub(/\n$/, '')
  end

  platform_gcp_opt = {
    "region" => (defined?(region) and (not region.nil?)) ? region : "us-central1",
    "projectID" => iaas.config[:project]
  }

  if defined?(existing_subnets) && existing_subnets && (existing_subnets.length > 0)
    platform_gcp_opt = platform_gcp_opt.merge(existing_subnets)
  end

  install_config["platform"]["gcp"] = platform_gcp_opt

  if defined?(vm_type) && vm_type
    vm_type_masters ||= vm_type
    vm_type_workers ||= vm_type
  end
  if vm_type_masters
    install_config["controlPlane"]["platform"] = {
      "gcp" => {
        "type" => vm_type_masters
      }
    }
  end
  if vm_type_workers
    install_config["compute"][0]["platform"] = {
      "gcp" => {
        "type" => vm_type_workers
      }
    }
  end

  env_vars.merge!({
    "GOOGLE_CREDENTIALS" => gcpcreds.path
  }) { |key, v1, v2| v1 ? v1 : v2 }

when "azure"
  azurecreds = Tempfile.new("azurecreds", Host.localhost.workdir)
  azurecreds.write("{\"subscriptionId\":\"#{iaas.azure_config[:subscription_id]}\",\"clientId\":\"#{iaas.azure_config[:auth][:client_id]}\",\"clientSecret\":\"#{iaas.azure_config[:auth][:client_secret]}\",\"tenantId\":\"#{iaas.azure_config[:auth][:tenant_id]}\"}")
  azurecreds.close
  # keep reference of temp file until installer exit to avoid it being deleted
  proc {
    _azurecreds = azurecreds
    at_exit { puts "deleting #{_azurecreds.path}"; _azurecreds.unlink }
  }.call

  install_config["baseDomain"] = iaas.azure_config[:install_base_domain]
  if iaas&.azure_config&.dig(:host_connect_opts, :ssh_private_key)
    ssh_key_path = expand_private_path(iaas.azure_config[:host_connect_opts][:ssh_private_key])
    install_config["sshKey"] = File.read(ssh_key_path.sub(/(?:\.pem)?$/, ".pub")).gsub(/\n$/, '')
  end

  platform_azure_opt = {
    "region" => (defined?(region) and (not region.nil?)) ? region : iaas.azure_config[:location],
    "baseDomainResourceGroupName" => iaas.azure_config[:resource_group]
  }

  if defined?(existing_subnets) && existing_subnets && (existing_subnets.length > 0)
    install_config["networking"]["machineNetwork"][0]["cidr"] = existing_subnets["virtualNetwork_CIDR"]
    platform_azure_opt = platform_azure_opt.merge(existing_subnets.reject {| key, value | key == "virtualNetwork_CIDR" })
  end

  install_config["platform"]["azure"] = platform_azure_opt

  if defined?(vm_type) && vm_type
    vm_type_masters ||= vm_type
    vm_type_workers ||= vm_type
  end
  if vm_type_masters
    install_config["controlPlane"]["platform"] = {
      "azure" => {
        "type" => vm_type_masters
      }
    }
  end
  if vm_type_workers
    install_config["compute"][0]["platform"] = {
      "azure" => {
        "type" => vm_type_workers
      }
    }
  end

  env_vars.merge!({
    "AZURE_AUTH_LOCATION" => azurecreds.path
  }) { |key, v1, v2| v1 ? v1 : v2 }

when "openstack"
  openstack_profile = "openstack"
  clouds_conf = {
    "clouds" => {
      openstack_profile => {
        "auth" => {
          "auth_url" => iaas.os_url.gsub(/\/auth\/tokens\/?$/,""),
          # "project_name" => "my-project-name",
          # "project_id" => "642c6ebd48bf42fa8a7fc245c7572e31",
          "username" => iaas.os_user,
          "password" => iaas.os_passwd,
          # "user_domain_name" => "example.com"
        },
        "region_name" => iaas.os_region,
        "interface" => "public",
        "identity_api_version" => iaas.os_url.include?("/v3") ? 3 : 2
      }
    }
  }
  if iaas.opts[:tenant_id_v4] || iaas.os_tenant_id || iaas.os_project_id
    clouds_conf["clouds"][openstack_profile]["auth"]["project_id"] = iaas.opts[:tenant_id_v4] || iaas.os_tenant_id || iaas.os_project_id
  end
  if iaas.os_tenant_name || iaas.os_project_name
    clouds_conf["clouds"][openstack_profile]["auth"]["project_name"] = iaas.os_tenant_name || iaas.os_project_name
  end
  if iaas.os_domain&.dig(:id)
    clouds_conf["clouds"][openstack_profile]["auth"]["user_domain_id"] = iaas.os_domain[:id]
  elsif iaas.os_domain&.dig(:name)
    clouds_conf["clouds"][openstack_profile]["auth"]["user_domain_name"] = iaas.os_domain[:name]
  end

  if defined?(openstack_cacert) && openstack_cacert
    os_cacert = Tempfile.new("cacert.crt.", Host.localhost.workdir)
    os_cacert.write Base64.decode64(openstack_cacert)
    os_cacert.close
    proc {
      _os_cacert = os_cacert
      at_exit { puts "deleting #{_os_cacert.path}"; _os_cacert.unlink }
    }.call
    clouds_conf["clouds"][openstack_profile]["cacert"] = "#{os_cacert.path}"
  end

  clouds_yaml = Tempfile.new("clouds.yaml.", Host.localhost.workdir)
  clouds_yaml.write clouds_conf.to_yaml
  clouds_yaml.close

  clouds_conf["clouds"][openstack_profile]["auth"]["password"] = "HIDDEN"
  logger.info "clouds configuration for openstack\n#{clouds_conf.to_yaml}"

  # keep reference of temp file until installer exit to avoid it being deleted
  proc {
    _clouds_yaml = clouds_yaml
    at_exit { puts "deleting #{_clouds_yaml.path}"; _clouds_yaml.unlink }
  }.call

  if defined?(command_terminate) && command_terminate
    fips = JSON.parse(File.read(File.absolute_path("workdir/install-dir") + "/fips_info"))
    fips["fips"].each { |fip|
      logger.info "Removing floating ip #{fip["floating_ip_address"]} from #{os_ext_network}"
      begin
        iaas.delete_floating_ip(fip["id"])
      rescue
        logger.warn "Remove floating ip got trouble\n #{fip}"
      end
    }
  else
    # we have to store floating ip info for deallocation
    if cluster_name.length > 14
      logger.warn "Your inputed cluster name - #{cluster_name} is longer than 14 for IPI on OSP, because dns limition, pls input another shorter one for one more try"
      exit 1
    end
    logger.info "Allocating new floating ip from #{os_ext_network}"
    api_port_fip = iaas.allocate_floating_ip(os_ext_network, reuse: false)
    ingress_port_fip = iaas.allocate_floating_ip(os_ext_network, reuse: false)
    File.write(install_dir_absolute + "/fips_info",JSON.dump({"fips"=> [api_port_fip, ingress_port_fip]}))
    platform_osp_opt = {
        "cloud" => openstack_profile,
        "computeFlavor" => vm_type,
        "externalNetwork" =>  os_ext_network,
        "lbFloatingIP" => api_port_fip["floating_ip_address"],
        "region" => iaas.os_region,
        "trunkSupport" => "1",
        "octaviaSupport" => "0"
    }
    if defined?(externalDNS) && externalDNS
      platform_osp_opt = platform_osp_opt.merge({"externalDNS" => externalDNS})
    end
    install_config["platform"]["openstack"] = platform_osp_opt

    # customize vm_types for different role
    masters_osp_opt = {}
    workers_osp_opt = {}

    if defined?(additionalNetworkIDs) && additionalNetworkIDs && additionalNetworkIDs.is_a?(Array)
      additionalNetworkIDs_masters ||= additionalNetworkIDs
      additionalNetworkIDs_workers ||= additionalNetworkIDs
    end

    if additionalNetworkIDs_masters && additionalNetworkIDs_masters.is_a?(Array)
      masters_osp_opt.merge!({"additionalNetworkIDs" => additionalNetworkIDs_masters})
    end

    if additionalNetworkIDs_workers && additionalNetworkIDs_workers.is_a?(Array)
      workers_osp_opt.merge!({"additionalNetworkIDs" => additionalNetworkIDs_workers})
    end

    if defined?(vm_rootvolume) && vm_rootvolume
      vm_rootvolume_masters ||= vm_rootvolume
      vm_rootvolume_workers ||= vm_rootvolume
    end

    if defined?(vm_rootvolume_masters) && vm_rootvolume_masters && vm_rootvolume_masters.is_a?(Hash)
      masters_osp_opt.merge!({ "rootVolume" => Collections.deep_hash_strkeys(vm_rootvolume_masters) })
    end
    if defined?(vm_rootvolume_workers) && vm_rootvolume_workers && vm_rootvolume_workers.is_a?(Hash)
      workers_osp_opt.merge!({ "rootVolume" => Collections.deep_hash_strkeys(vm_rootvolume_workers) })
    end


    if vm_type_masters
      masters_osp_opt.merge!({ "type" => vm_type_masters })
    end

    if vm_type_workers
      workers_osp_opt.merge!({ "type" => vm_type_workers })
    end

    unless masters_osp_opt.empty?
      install_config["controlPlane"]["platform"] = {
        "openstack" => masters_osp_opt
      }
    end

    unless workers_osp_opt.empty?
      install_config["compute"][0]["platform"] = {
        "openstack" => workers_osp_opt
      }
    end

    zone = dns_component
    install_config["baseDomain"] = "#{zone}.#{conf[:services, :dyndns, :zone]}"
    install_config["networking"]["machineNetwork"][0]["cidr"] = "192.168.0.0/18"
    if iaas&.opts&.dig(:host_opts, :ssh_private_key)
      ssh_key_path = expand_private_path(iaas.opts.dig(:host_opts, :ssh_private_key))
      ENV["OPENSHIFT_INSTALL_SSH_PUB_KEY_PATH"] = ssh_key_path.sub(/(?:\.pem)?$/, ".pub")
      install_config["sshKey"] = File.read(ENV["OPENSHIFT_INSTALL_SSH_PUB_KEY_PATH"]).strip
    end
    if defined?(enable_proxy) && enable_proxy && enable_proxy.to_s.downcase == "yes"
      install_config["proxy"]["noProxy"] = no_proxy + ",oauth-openshift.apps.#{cluster_name}.#{zone}.#{conf[:services, :dyndns, :zone]}"
    end
  end

  env_vars.merge!({
    "OS_CLIENT_CONFIG_FILE" => clouds_yaml.path,
    "OPENSHIFT_INSTALL_OPENSTACK_CLOUD" => openstack_profile,
    "OPENSHIFT_INSTALL_OPENSTACK_REGION" => iaas.os_region,
    "OPENSHIFT_INSTALL_OPENSTACK_EXTERNAL_NETWORK" => os_ext_network
  }) { |key, v1, v2| v1 ? v1 : v2 }

  # reason why put dns here not a install_sequence
  # 1. if use install_sequence, I have to introduce a varibale for openstack
  # with a if statement to only work with openstack, but this need all template
  # have a update to not met variable not defined error
  # 2. with put dns logic here, I do not need create a new template for IPI on OSP only,
  # means more consistent with others
  if defined?(command_terminate) && command_terminate
    # delete dns records and floating ip to release resources
    # begin
    #   tmp_dyn = get_dyn
    #   logger.info "Removing api and apps records for #{cluster_name}"
    #   tmp_dyn.dyn_delete_matching_records(/\.#{cluster_name}\./)
    #   tmp_dyn.publish
    # rescue
    #   logger.warn "dyn remove records got some trouble, maybe lack of creds"
    # end
  else
    # create dyn dns to make external can access the cluster for both api and routes
    begin
      tmp_dyn = get_dyn
      tmp_dyn.dyn_create_a_records("api.#{instances_name_prefix}.#{zone}" , [api_port_fip["floating_ip_address"]])
      tmp_dyn.dyn_create_a_records("api-int.#{instances_name_prefix}.#{zone}" , ["192.168.0.5"])
      tmp_dyn.dyn_create_a_records("*.apps.#{instances_name_prefix}.#{zone}", [ingress_port_fip["floating_ip_address"]])
      tmp_dyn.publish
    rescue => e
      logger.error "Error creating Dynect DNS records: #{exception_to_string(e)}"
    end
  end
end


File.write(
  File.join(install_dir_absolute, "install-config.yaml"),
  install_config.to_yaml
)

if ssh_key_path
  File.expand_path("~/.ssh").tap { |ssh_dir|
    unless Dir.exist? ssh_dir
      Dir.mkdir ssh_dir
      File.chmod 700, ssh_dir
    end
    f = Tempfile.new(["ocp-bootstrap-", ".pem"], ssh_dir)
    f.write File.read(ssh_key_path)
    f.close
  }
end

when "vsphere"
  aws_iaas = iaas_by_service('AWS-CI')
  awsprofile = "flexy-installer"
  awscreds = Tempfile.new("awscreds", Host.localhost.workdir)
  awscreds.write("[#{awsprofile}]\n" \
                 "aws_access_key_id = #{aws_iaas.access_key}\n" \
                 "aws_secret_access_key = #{aws_iaas.secret_key}\n")
  awscreds.close
  # keep reference of temp file until installer exit to avoid it being deleted
  proc {
    _awscreds = awscreds
    at_exit { puts "deleting #{_awscreds.path}"; _awscreds.unlink }
  }.call

  install_config["baseDomain"] = iaas.config[:install_base_domain]
  if iaas&.config&.dig(:host_connect_opts, :ssh_private_key)
    ssh_key_path = expand_private_path(iaas.config[:host_connect_opts][:ssh_private_key])
    install_config["sshKey"] = File.read(ssh_key_path.sub(/(?:\.pem)?$/, ".pub")).gsub(/\n$/, '')
  end

  # customize vm_types for different role
  masters_vsphere_opt = {
    "cpus" => (define?(master_num_cpus) and (not master_num_cpus.nil?)) ? master_num_cpus : num_cpus
    "memoryMB" => (define?(master_num_memory) and (not master_num_memory.nil?)) ? master_num_memory : memory
  }
  workers_vsphere_opt = {
    "cpus" => (define?(worker_num_cpus) and (not worker_num_cpus.nil?)) ? worker_num_cpus : num_cpus
    "memoryMB" => (define?(worker_num_memory) and (not worker_num_memory.nil?)) ? worker_num_memory : memory
  }
  master_disksize_opt = {
    "diskSizeGB" = (define?(master_disk_size) and (not master_disk_size.nil?)) ? master_disk_dize : disk_size
  }
  worker_disksize_opt = {
    "diskSizeGB" = (define?(worker_disk_size) and (not worker_disk_size.nil?)) ? worker_disk_size: disk_size
  }

  if ! master_disksize_opt.empty?
    masters_vsphere_opt = masters_vsphere_opt.merge({"osDisk" => master_disksize_opt})
  end

  if ! worker_disksize_opt.empty?
    workers_vsphere_opt = workers_vsphere_opt.merge({"osDisk" => worker_disksize_opt})
  end

  if ! masters_vsphere_opt.empty?
    install_config["controlPlane"]["platform"] = {
      "vsphere" => masters_vsphere_opt
    }
  end
  if ! workers_vsphere_opt.empyt?
    install_config["compute"]["platform"] = {
      "vsphere" => worker_vsphere_opt
    }
  end

  #Trust the vsphere certification on installation server
  vcenter_host = iaas.config[:connect][:host]
  cmd="wget https://#{vcenter_host}/certs/download.zip --no-check-certificate"
  system("#{cmd}")
  cmd="unzip -o download.zip 'certs/lin/*' -d /tmp/ && \
       cp -f /tmp/certs/lin/* /etc/pki/ca-trust/source/anchors/ && \
       rm -rf download.zip /tmp/certs && \
       update-ca-trust extract"
  system("#{cmd}")

  # Reserve virutal IP address for apiVIP, IngressVIP, DNSVIP from IPAM server
  vsphere_network = iaas.config[:common][:CIDR]
  vsphere_basedomain = iaas.config[:install_base_domain]
  shell_script = localize('ipi-config-vsphere-vip-dns.sh', File.dirname(__FILE__) + "/../")
  if defined?(command_terminate) && command_terminate
    cmd = "'#{shell_script}' '#{cluster_name}' '#{vsphere_network.partition('/')[0]}' '#{vsphere_basedomain}' 'DELETE'"
    puts "Command: #{cmd}"
    system("${cmd}")
    if not $?.success?
      exit 2
    end
  else
    cmd = "'#{shell_script}' '#{cluster_name}' '#{vsphere_network.partition('/')[0]}' '#{vsphere_basedomain}' 'ADD'"
    puts "Command: #{cmd}"
    vips = `#{cmd}`
    if not $?.success?
      exit 2
    end
    puts "vip list: #{vips}"
  end

  platform_vsphere_opt = {
    "datacenter" => iaas.config[:common][:datacenter]
    "defaultDatastore" => iaas.config[:common][:datastore]
    "password" => iaas.config[:connect][:password]
    "username" => iaas.config[:connect][:username]
    "vCenter" => iaas.config[:connect][:host]
    "apiVIP" => #{vips.partition(',')[0]}
    "IngressVIP" => #{vips.chomp.partition(',')[2]}
  }
  install_config["platform"]["vsphere"] = platform_vsphere_opt

  env_vars.merge!({
    "AWS_DEFAULT_REGION" => 'us-east-2',
    "AWS_PROFILE" => awsprofile,
    "AWS_SHARED_CREDENTIALS_FILE" => awscreds.path,
  }) { |key, v1, v2| v1 ? v1 : v2 }

end

case cloud_type
when "vsphere"
    install_config["platform"]["vsphere"]["password"] = "HIDDEN"
end

if defined?(enable_proxy) && enable_proxy && enable_proxy.to_s.downcase == "yes"
  cluster_info_data.merge!(install_config["proxy"])
end
File.write(
  cluster_info_json_file,
  cluster_info_data.to_json
)

logger.info "install-config.yaml:\n" +
  install_config.merge({"pullSecret" => "HIDDEN"}).to_yaml

env_vars

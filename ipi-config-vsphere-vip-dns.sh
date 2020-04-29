#/bin/bash
set -x
if [ $# -ne 4 ]; then
  echo "Invalid argument, usage: $0 <cluster_name> <network> <base_domain> <ADD/DELETE>"
  exit 1
fi

cluster_name=$1
network=$2
base_domain=$3
action=$4
ipam="139.178.89.254"
ipam_token="EYmMFjaaQDNp7i1MlHRUZ0kPZC2hUHky"
cluster_domain="${cluster_name}.${base_domain}"
hosted_zone_id="$(aws route53 list-hosted-zones-by-name \
            --dns-name "${base_domain}" \
            --query "HostedZones[? Config.PrivateZone != \`true\` && Name == \`${base_domain}.\`].Id" \
            --output text)"

declare -a vips

assign_vips(){

  echo "Reserving virtual ip address from the IPAM server"
  for i in {0..1}
  do
    args=$(jq -n \
            --arg nw "$network" \
            --arg hn "$cluster_name-$i" \
            --arg ipamip "$ipam" \
            --arg token "$ipam_token" \
            '{network: $nw , hostname: $hn, ipam: $ipamip, ipam_token: $token}')

    vip_json=$(echo "$args" | bash <(curl -s https://raw.githubusercontent.com/openshift/installer/master/upi/vsphere/ipam/cidr_to_ip.sh))
    vips[$i]=$(echo "$vip_json" | jq -r .ip_address )
    echo "$cluster_name-$i: vips[$i]"
  done
}

get_vips(){

  echo "Get leased IP address from IPAM server"
  for i in {0..1}
  do
    vips[$i]=$(curl -s "http://${ipam}/api/getIPs.php?apiapp=address&apitoken=${ipam_token}&domain=${cluster_name}-$i" | jq -r .\""${cluster_name}-$i"\")
  done

}

remove_vips(){
  echo "Releasing IP address from IPAM server"
  for i in {0..1}
  do
    curl -s "http://${ipam}/api/removeHost.php?apiapp=address&apitoken=${ipam_token}&host=${cluster_name}-$i"
  done
}

create_dns(){
 cat > dns-create.json <<EOF
 {
   "Comment": "Create public openshift DNS records for vsphere/ipi install",
   "Changes": [{
    "Action": "UPSERT",
    "ResourceRecordSet": {
      "Name": "api.$cluster_domain.",
      "Type": "A",
      "TTL": 60,
      "ResourceRecords": [{"Value": "${vips[0]}"}]
      }
    },{
    "Action": "UPSERT",
    "ResourceRecordSet": {
      "Name": "*.apps.$cluster_domain.",
      "Type": "A",
      "TTL": 60,
      "ResourceRecords": [{"Value": "${vips[1]}"}]
      }
   }]
 }
EOF
 
 result=`aws route53 change-resource-record-sets --hosted-zone-id "$hosted_zone_id" --change-batch file://dns-create.json`
 aws_id=`echo $result | awk -F' ' '{print $(NF-2)}'`
 #rm -rf dns-create.json
 echo $aws_id
}

delete_dns(){
  cat > dns-delete.json <<EOF
  {
    "Comment": "Delete public openshift DNS records for vsphere ipi install",
    "Changes": [{
      "Action": "DELETE",
      "ResourceRecordSet": {
        "Name": "api.$cluster_domain.",
        "Type": "A",
        "TTL": 60,
        "ResourceRecords": [{"Value": "${vips[0]}"}]
       }
    },{
    "Action": "DELETE",
    "ResourceRecordSet": {
      "Name": "*.apps.$cluster_domain.",
      "Type": "A",
      "TTL": 60,
      "ResourceRecords": [{"Value": "${vips[1]}"}]
      }
    }]
  }
EOF
  result=`aws route53 change-resource-record-sets --hosted-zone-id "$hosted_zone_id" --change-batch file://dns-delete.json`
  aws_id=`echo $result | awk -F' ' '{print $(NF-2)}'`
  #rm -rf dns-delete.json
  echo $aws_id
}

check_route53_status(){
   aws_id=$1
   loop=10
   while [ $loop -ge 0 ]
   do
     aws_status=`aws route53  get-change --id $aws_id | grep INSYNC | wc -l`
     if [ $aws_status -gt 0 ]; then
       echo "aws route53 status has been insync..."
       break
     else
       echo "aws route53 status is still in PENDING..."
       sleep 30s
       loop=$((loop - 1))
     fi
   done
}

id=""
if [ "X$action" == "XADD" ]; then
  assign_vips  
  echo "Adding Route53 DNS records..."
  id="$(create_dns)"
    
elif [ "X$action" == "XDELETE" ]; then
  get_vips
  remove_vips
  echo "Deleting Route53 DNS records..."
  id="$(delete_dns)"
fi

[ "x$id" != "x" ] && check_route53_status $id

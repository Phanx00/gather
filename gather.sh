#!/bin/bash

CYAN="\e[0;36m"
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW="\033[0;33m"
NC='\033[0m'

echo -e "${CYAN}  _______      ___   .___________. __    __   _______ .______      ${NC}";
echo -e "${CYAN} /  _____|    /   \  |           ||  |  |  | |   ____||   _  \     ${NC}";
echo -e "${CYAN}|  |  __     /  ^  \ \`---|  |----\`|  |__|  | |  |__   |  |_)  |    ${NC}";
echo -e "${CYAN}|  | |_ |   /  /_\  \    |  |     |   __   | |   __|  |      /     ${NC}";
echo -e "${CYAN}|  |__| |  /  _____  \   |  |     |  |  |  | |  |____ |  |\  \----.${NC}";
echo -e "${CYAN} \______| /__/     \__\  |__|     |__|  |__| |_______|| _| \`._____|${NC}";
echo -e "${CYAN}                                                                   ${NC}";



#nmap_path
#katana_path
#nuclei_path
#dalfox_path
#dirsearch_path
#httpx_path
#dnsx_path
#assetfinder_path
#findomain_path
#subfinder_path
#paramspider_path
#secretfinder_path
#gowitness_path
#linkfinder_path
#misconfig-mapper_path
#intercatsh-client_path


katana_result="" # katana static finding
targets="" # working file
live_target=""
domains_tmp="" # working file for domain
subdomains="" # list of valif subdomain
nuclei_vuln=""
technologies=""
cves=""
targets_url="" # urls with param
dalfox_out=""
dalfox_blind_out=""
statics=""
findings=""
nuclei_findings=""
nuclei_headers=""
dirsearch=""
takeover=""
dalfox_log=""
link=""
mapping=""
domains=""
interact_session=""
interact_output=""
response=""
js=""
dir_name=""
log=""
dns_result=""



s_flag=false # flag for search subdomains
m_flag=false # flag for use mapper
b_flag=false # flag for blind XSS


usage() {
  echo -e "Use -i for IP/CIDR or -d for file with domains\n -a for active scan (optional)\n -s for enable subdomain search with domain" 1>&2
}

exit_abnormal() {
  usage
  exit 1
}

update_variable() {
    mkdir -p "$dir_name/scope/"
    mkdir -p "$dir_name/scans/"
    mkdir -p "$dir_name/nmap/"

    katana_result="katana_result.txt" # katana static finding
    targets=$dir_name/scope/target.txt # working file
    live_target=$dir_name/scope/live_target.txt
    domains_tmp=$dir_name/domains.tmp # working file for domain
    subdomains=$dir_name/scope/subdomains.txt # list of valif subdomain
    nuclei_vuln=nuclei_vuln.txt
    technologies=technologies.txt
    cves=cves.txt
    targets_url=targets_url.txt # urls with param
    dalfox_out=dalfox.txt
    dalfox_blind_out=dalfox_blind.txt
    statics=statics.txt
    findings=findings.txt
    nuclei_findings=nuclei_findings.txt
    nuclei_headers=nuclei_missing_headers.txt
    dirsearch=dirsearch.txt
    takeover=takeover.txt
    dalfox_log=dalfox.log
    link=link.txt
    mapping=$dir_name/mapping.txt
    domains=$dir_name/domains.txt
    interact_session=interact_session.txt
    interact_output=interact_output.txt
    response=$dir_name
    js=$dir_name/js
    log=$dir_name/log.log
    dns_result=$dir_name/scope/dns_ptr.txt  # domain retrived from IP
    scans=$dir_name/scans
    scope=$dir_name/scope
    nmap=$dir_name/nmap

}

check_input_type() {
    local input=$1
     # check single IP
    if [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "IP"
    # Check CIDR
    elif [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        echo "CIDR"
    else
        exit_abnormal
    fi
}

check_ip_equality() {
    local ip1=$1
    local ip2=$2

    if [[ "$ip1" == "$ip2" ]]; then
        return 0  
    else
        return 1  
    fi
}


check_ip_in_cidr() {
    local ip=$1
    local cidr=$2

    network=$(echo "$cidr" | cut -d "/" -f 1)
    netmask=$(echo "$cidr" | cut -d "/" -f 2)

    IFS=. read -r ip1 ip2 ip3 ip4 <<< "$ip"
    IFS=. read -r net1 net2 net3 net4 <<< "$network"

    net_int=$(( (net1 << 24) + (net2 << 16) + (net3 << 8) + net4 ))

    ip_int=$(( (ip1 << 24) + (ip2 << 16) + (ip3 << 8) + ip4 ))

    mask=$(( (1 << 32) - (1 << (32 - netmask)) ))


    if [ $((ip_int & mask)) -eq $((net_int & mask)) ]; then
        return 0
    else
        return 1
    fi
}



check_scope() {
     local result_tmp=$dir_name/result.tmp 
     local temp=$dir_name/temp.tmp
    
     echo -e "${YELLOW}[-] Checking the scope${NC}"
     if [ -n "$ip" ]; then
         sort -u $1 | httpx -silent | dnsx -silent -a -resp -nc > $result_tmp

         input_type=$(check_input_type "$ip")
         case $input_type in
             "CIDR")
                 while IFS= read -r line; do
                     ip_wk=$(echo -e "$line" | awk '{print $3}' | grep -oP '(?<=\[).*?(?=\])')
                     if check_ip_in_cidr "$ip_wk" "$ip"; then
                         echo $line | awk '{print $1}' >> $targets 
                     fi
                 done < "$result_tmp"
                 ;;
             "IP")
                 while IFS= read -r line; do
                     ip_wk=$(echo -e "$line" | awk '{print $3}' | grep -oP '(?<=\[).*?(?=\])')
                     if check_ip_equality "$ip_wk" "$ip"; then
                         echo $line | awk '{print $1}' >> $targets 
                     fi
                 done < "$result_tmp"
                 ;;
             *)
                 echo -e "${RED}Wrong IP: $ip_tmp${NC}"
                 ;;
         esac
         rm $result_tmp
     else
         local valid_domains=()
         while IFS= read -r line; do
             valid_domains+=("$line")
         done <  "$dir_name/$domain"


         while IFS= read -r domain_value; do
             found=false
             for valid_domain in "${valid_domains[@]}"; do
                 if [[ "$domain_value" == *"$valid_domain" || "$domain_value" == "$valid_domain" || "$domain_value" == *".$valid_domain" ]]; then
                     found=true
                     break
                 fi
             done

             if [ "$found" = true ]; then
                 echo "$domain_value" >> $targets
             fi
         done < "$1"
     fi

    if [[ -s $targets ]]; then
        sort -u "$targets" > "$temp" &&  mv "$temp" "$targets"
    fi

    httpx -l $targets --silent  -sr -srd $response > $live_target 2>> $log
    echo -e "${GREEN}[+] Scope checked${NC}"
}



nmap_check(){
    local nmap_result=$dir_name/nmap/all
    echo -e "${YELLOW}[-] Start NMAP enumeration${NC}"
    nmap -sC -sV $ip -oA $nmap_result 1>>/dev/null 2>>$log
    cat $nmap/all.nmap | grep -o 'DNS:[^,]*' | awk -F: '{print $2}'  | sort | uniq > $dns_result
    echo -e "${GREEN}[+] NMAP enumeration completed. Result saved in:${NC} ${CYAN}$nmap_result${NC}"
}


dns_enum() {
    echo -e "${YELLOW}[-] Start DNS enumeration${NC}"
    echo $ip| dnsx -silent -resp-only -ptr >> $dns_result 2>> $log
    if [ ! -s $dns_result ]; then
        echo -e "${GREEN}[+] DNS enumeration completed.${NC} ${RED}0 Results. Quitting.${NC}"
        exit 0
    else
        echo -e "${GREEN}[+] DNS enumeration completed. Result saved in:${NC} ${CYAN}$dns_result${NC}"
    fi
}

statics_enum() {
    echo -e "${YELLOW}[-] Start statics enumeration with Katana${NC}"


    for url in $(cat $live_target); do
        local result_katana="$scans/${url#*//}/$katana_result" 
        mkdir "$scans/${url#*//}"
        katana -silent -u $url  -d 5 -jc -kf all -fx -xhr -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg > $result_katana 2>> $log
        urlfinder -silent -d $url >> $result_katana 2>> $log
    done
    echo -e "${GREEN}[+] Statics enumeration completed. Result saved in:${NC} ${CYAN} $scans ${NC}"
}


 search_subdomain() {
     local sub1="$dir_name/subdomains-1.txt"
     local sub2="$dir_name/subdomains-2.txt" 
     local sub3="$dir_name/subdomains-3.txt" 
     local tmp="$dir_name/tmp.txt" 
    
     echo -e "${YELLOW}[-] Start finding subdomains${NC}"
     cat $dns_result >> $subdomains # need to check the IP for the resolved DNS
     cat $dns_result | assetfinder --subs-only | grep -v "[INF]"  > $sub1 2>> $log &
     findomain -q -f $dns_result > $sub2 2>> $log &
     subfinder -dL $dns_result -silent -all -nc > $sub3 2>> $log &
     wait

     echo -e "${YELLOW}[-] Merge of subdomains${NC}"
     cat $sub1 $sub2 $sub3 |alterx --silent -en >> $tmp 2>>$log 

     sort -u $tmp > $subdomains
     rm $tmp $dir_name/subdomains-*

    check_scope $subdomains
    echo -e "${GREEN}[+] Subdomain enumeration completed. Result saved in:${NC} ${CYAN}$subdomains${NC}"
    echo -e "${GREEN}[+] Valid targets saved in:${NC} ${CYAN}$targets${NC}\n${GREEN}[+] Live targets saved in:${NC}${CYAN}$live_target${NC}"
}


retrive_params(){
    echo -e "${YELLOW}[-] Start parameters discover for live targets${NC}"
    local results="results"
    while IFS= read -r url; do
        echo -e "${YELLOW}[-] Start parameters discover for: ${NC}${CYAN}$url${NC}"
        local temp=$dir_name/temp.tmp
        local targets_local=$scans/${url#*//}/$targets_url

        katana --silent -f qurl -iqp -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -u "$url" -fx > "$targets_local"
        paramspider -d ${url#*://} 1>/dev/null 2>> $log            
        if [ -s "$results/" ]; then
            if [ "$(ls -A $results/)" ]; then
                cat $results/* >> $scans/${url#*//}/$targets_url
                rm -rf $results
            fi
        fi
        echo -e "${YELLOW}[+] Parameters discover completed for ${NC}${CYAN}$url${NC}${YELLOW}.Results saved in:${NC}${CYAN}$scans/${url#*//}/$targets_url${NC}"
    done < "$live_target"
    echo -e "${GREEN}[+] Parameters discover completed for live targets."${NC}
}
        

nuclei_check() {
    echo -e "${YELLOW}[-] Start enumeration with Nuclei for live targets${NC}"
    nuclei --silent -ut >/dev/null
    while IFS= read -r url; do
        echo -e "${YELLOW}[-] Start enumeration for:${NC}${CYAN}$url${NC}"
        nuclei --silent -fr -t technologies -u "$url"  -nc > $scans/${url#*//}/$technologies
        nuclei --silent -fr -t cves -u "$url"  -nc > $scans/${url#*//}/$cves
        # nuclei --silent  -dast -u $url > $scans/${url#*//}/$nuclei_vuln not work
        nuclei --silent -fr -id http-missing-security-headers -u "$url" -nc > $scans/${url#*//}/$nuclei_headers
        nuclei --silent -fr -t takeovers -u "$url" -nc > $scans/${url#*//}/$takeover
        echo -e "${YELLOW}[+] Nuclei enumeration completed for ${CYAN}$url${NC}.${YELLOW}\nResults saved in:${NC}${CYAN}\n$scans/${url#*//}/$technologies\n$scans/${url#*//}/$cves\n$scans/${url#*//}/$nuclei_vuln\n${CYAN}$scans/${url#*//}/$takeover\n$scans/${url#*//}/$nuclei_headers\n${NC}"
    done < "$live_target"
    echo -e "${GREEN}[+] Nuclei enumeration completed.${NC}"
}

dalfox_check(){
    echo -e "${YELLOW}[-] Start XSS check with Dalfox for valid url${NC}"
    for target in $(ls $scans);do
        if [[ -s $scans/$target/$targets_url ]]; then
        echo -e "${YELLOW}[-] Start XSS check with Dalfox for ${NC}${CYAN}$target${NC}"
        dalfox file $scans/$target/$targets_url --remote-payloads=portswigger,payloadbox --waf-evasion > $scans/$target/$dalfox_out 2> $scans/$target/$dalfox_log
        echo -e "${GREEN}[+] XSS completed. Results saved in:${NC}${CYAN}$dalfox_out${NC}"
            # ############################### TEST BLIND XSS ############################### #
            if [[ "$b_flag" = true ]]; then
                echo -e "${YELLOW}[-] Start XSS Blind check with Dalfox for $target${NC}"
                interactsh-client -v -sf $scans/$target/$interact_session > $scans/$target/$interact_output 2>&1 &
                sleep 10
                local remote=$(cat $scans/$target/$interact_output| sed -r 's/\x1B\[[0-9;]*[mK]//g' | grep "\[INF\]" | awk 'NR==3' | cut -d " "  -f 2)
                echo $remote
                remote="http://$remote"
                echo $remote  
                dalfox file $scans/$target/$targets_url --waf-evasion -b $remote > $dalfox_blind_out 2>> $dalfox_log
                echo -e "${GREEN}[+] XSS Blind completed. Results saved in:${NC}${CYAN}$scans/$target/$dalfox_blind${NC}"
            fi
            # ############################### TEST BLIND XSS ############################### #
        else
            echo -e "${YELLOW}[-] Not valid urls found. Dalfox check skipped for${NC}${CYAN} $url${NC}"
        fi
    done
}

secret_check(){
    echo -e "${YELLOW}[-] Start secrets finding for live targets${NC}"
    for dir in $(ls $scans);do
        echo -e "${YELLOW}[-] Start secrets finding for: ${NC}${CYAN}$dir${NC}"
        local temp=$scans/$dir/temp.tmp
        katana  -u $scans/$dir/$katana_result --silent -em js -d 5 -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg > $temp 
        sort -u $temp > $scans/$dir/$statics
        echo "" > $temp

        for i in $(cat $scans/$dir/$katana_result);do
            python "$(pipx runpip LinkFinder show LinkFinder | awk -F ': ' '/Location/ {print $2 "/linkfinder.py"}')" -i $i -d -o cli | grep -a -v "Running against" | grep -a -v "^$" | grep -a -v "Invalid input defined or SSL error for:" | grep -a -v "Usage" >>  $temp 2>>$log
        done

        sort -u $temp | grep -ivf clear-list.txt > $scans/$dir/$link
        echo "" > $temp

        if [[ -s  $scans/$dir/$statics ]]; then
            mkdir $scans/$dir/findings
            c=1
            for i in $(cat  $scans/$dir/$statics);do
                if curl -s $i | grep -q "//# sourceMappingURL=data:application/json;charset=utf-8;base64"; then
                    echo "${YELLOW}Secretfinder for ${NC}${CYAN}$i${NC}${YELLOW}skipped. The content could block its execution. Manual execution with ${NC}${CYAN}secretfinder -i $i -g 'jquery;bootstrap;api.google.com' -o cli > $scans/$dir/findings/$c.txt${NC}"
                else
                    secretfinder -i $i -g 'jquery;bootstrap;api.google.com' -o cli > $scans/$dir/findings/$c.txt
                fi
                ((c=c+1))
            done

            cat  $scans/$dir/findings/* >> $temp
            sort -u $temp > $scans/$dir/findings/$findings
                echo -e "${YELLOW}[+] Secret findings for ${CYAN}$dir${NC}${YELLOW} completed. Results saved in the directory ${NC}${CYAN}$scans/$dir/findings/ ${NC}${YELLOW} unique result saved in: ${NC}${CYAN}$scans/$dir/findings/$findings${NC}"
            else
                echo -e "${YELLOW}[-] Statics not found for ${CYAN}$dir${NC}${YELLOW} SecretFinder skipped${NC}"
            fi
        rm $temp
        echo -e "${YELLOW}[-] Start secrets finding with nuclei for ${CYAN}$dir${NC}"
        nuclei -t javascript/enumeration -u $dir --silent > $scans/$dir/$nuclei_findings
        #https://github.com/w9w/JSA/tree/main/templates
        if [[ -n "$domain" ]];then
            nuclei -t JSA -u $dir --silent | grep "PII" | grep -v "\"\""  >> $scans/$dir/$nuclei_findings
        else	
            nuclei -t JSA -u $dir --silent | grep "PII" | grep -v "\"\""  >> $scans/$dir/$nuclei_findings
        fi
        echo -e "${GREEN}[+] Secret findings completed for ${CYAN}$dir${NC}.${GREEN} Results saved in:${NC}${CYAN}$scans/$dir/$nuclei_findings${NC} ${GREEN}and${NC} ${CYAN}$scans/$dir/$link${NC}"

    done
        echo -e "${GREEN}[+] Secret findings for live targets${NC}${YELLOW}completed${NC}"

}


dir_search() {
    echo -e "${YELLOW}[-] Start directory enumeration${NC}"
    if [ -n "$domain" ];then
    	if [[ "$s_flag" = false ]]; then
       		httpx -l $targets --silent -sr -srd $response > $live_target
    	fi
    fi  

    while IFS= read -r url; do
        dirsearch -u "$url" --log "$scans/${url#*//}/dirsearch_log.txt" --crawl -r -q -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json -O plain -o "$scans/${url#*//}/$dirsearch" 1>/dev/null 2>/dev/null
        echo -e "${GREEN}[+] Directory enumeration completed for ${NC}${CYAN}$url${NC}.${GREEN}Results saved in:${NC}${CYAN}$scans/${url#*//}/$dirsearch${NC}"
    done < "$live_target"
   # else
    #    Nmap parser not work anymore in dirsearch
    #    dirsearch --nmap-report $nmap/all.xml  --crawl -r -q -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json -O plain -o $scope/$dirsearch 1>/dev/null 2>/dev/null
        echo -e "${GREEN}[+] Directory enumeration completed for${NC}${CYAN}$url${NC}${GREEN}.Results saved in:${NC}${CYAN}$scope/$dirsearch${NC}"
    #fi
    echo -e "${GREEN}[+] Directory enumeration completed."
}

screenshot() {
    echo -e "${YELLOW}[-] Take screenshots ${NC}"
    #if [ -n "$domain" ]; then
    #    gowitness file -f $live_target --screenshot-fullpage -q 2>$log
    mkdir $dir_name/screenshot
    if [ -n "$ip" ]; then
        gowitness scan nmap -f $dir_name/nmap/all.xml -o --screenshot-fullpage --write-db -q 2>>$log
    fi
        gowitness scan file -f $live_target --screenshot-fullpage --write-db  -q 2>>$log
   
    mv  gowitness.sqlite3 $dir_name/screenshot/
    
    echo -e "${GREEN}[+] Screenshot taken. Results saved in:${NC}${CYAN}$dir_name/screenshot${NC}\n${YELLOW}Run ${CYAN}gowitness report server${NC}${YELLOW} for check the report${NC}"
}


mapper() {
    echo -e "${YELLOW}[-] Mapping vulnerabilities ${NC}"
    awk -F'.' '{print $(NF-1)}' $(cat $target | httpx --silent ) | sort | uniq > $domains
    for d in $(cat $domains);do
        misconfig-mapper -target $d -service "*"  | grep -v "\[-\]" >> $mapping
    done;
    echo -e "${GREEN}[+] Mapping completed. Results saved in:${NC}${CYAN}$mapping${NC}"
}


passive() {
    date >> $log
    check_input_type $ip >/dev/null
    echo -e "${GREEN}[+] Working for the IP/CIDR:${NC} ${CYAN}$ip${NC}"
    echo -e "${GREEN}[+] The output will be saved in the directory:${NC}${CYAN} $dir_name${NC}"
    nmap_check
    dns_enum    
    search_subdomain
    statics_enum
    screenshot
    secret_check
    echo -e "${GREEN}[+] Passive scans completed${NC}"
}


active() {
    retrive_params
    nuclei_check
    dalfox_check
    dir_search
    if [[ "$m_flag" = true ]]; then
    	mapper
    fi
    killall interactsh-client 2>/dev/null   # kill running interactsh at the end of full scan
    echo -e "${GREEN}[+] Active scans completed${NC}"
}


domain() {
    echo -e "${YELLOW}[-] Avvio scansione per domini dal file:${NC} ${CYAN}$domain${NC}"
    cat "$domain" > "$dns_result"

    if [[ "$s_flag" = true ]]; then
        search_subdomain
    else
        echo -e "${YELLOW}[-] Verifica domini con httpx${NC}"
        httpx -l "$domain" --silent -sr -srd "$response" > "$live_target"
    fi

    if [[ -s "$live_target" ]]; then
        echo -e "${YELLOW}[-] Generazione file targets da live_target${NC}"
        # Estrae dominio/host dallo schema completo (es. https://example.com → example.com)
        cat "$live_target" | awk -F/ '{print $3}' | sort -u > "$targets"
        echo -e "${GREEN}[+] File targets creato:${NC} ${CYAN}$targets${NC}"
    else
        echo -e "${RED}[!] Nessun target vivo trovato con httpx${NC}"
    fi

    statics_enum
    screenshot
    secret_check
}



while getopts ":i:d:asmb" options; do
  case "${options}" in
    i)
        ip=${OPTARG}
        ;;
    d)
        domain=${OPTARG}
        ;;
    a)
        a_flag=true
        ;;
    s)
        s_flag=true
        ;;
    m)
    	m_flag=true
    	;;
    b)
    	b_flag=true
    	;;
    :)
        echo -e "${GREEN}[!] Error: Option -$OPTARG requires an argument.${NC}" >&2
        exit_abnormal
        ;;
    *)
        exit_abnormal
        ;;
  esac
done


if [[ -z "$ip" && -z "$domain" ]]; then
  exit_abnormal
else
  if [[ -n "$ip" ]]; then
    dir_name="${ip%/*}"  
    mkdir -p "$dir_name"
    update_variable
    passive
  fi

  if [[ -n "$domain" ]]; then
    dir_name="${domain%.*}"  
    update_variable
    domain
  fi

  if [[ "$a_flag" = true ]]; then
      active
  fi
  exit 0
fi

#!/bin/bash

CYAN="\e[0;36m"
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW="\e[0;33m"
NC='\033[0m'

echo -e "${CYAN}  _______      ___   .___________. __    __   _______ .______      ${NC}";
echo -e "${CYAN} /  _____|    /   \  |           ||  |  |  | |   ____||   _  \     ${NC}";
echo -e "${CYAN}|  |  __     /  ^  \ \`---|  |----\`|  |__|  | |  |__   |  |_)  |    ${NC}";
echo -e "${CYAN}|  | |_ |   /  /_\  \    |  |     |   __   | |   __|  |      /     ${NC}";
echo -e "${CYAN}|  |__| |  /  _____  \   |  |     |  |  |  | |  |____ |  |\  \----.${NC}";
echo -e "${CYAN} \______| /__/     \__\  |__|     |__|  |__| |_______|| _| \`._____|${NC}";
echo -e "${CYAN}                                                                   ${NC}";

# --------------------------------------------------------
# Variabili globali e default per DNS-safe behaviour
# --------------------------------------------------------
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

# DNS-safety settings (regolabili)
DNS_CHUNK_SIZE=200    # linee per batch (split)
DNS_CONCURRENCY=5     # concorrenza xargs (-P)
DNS_PAUSE=0.5         # pausa (s) tra batch
RESOLVERS_FILENAME="resolvers.txt" # verrà creato in $dir_name

# Variabili Proxy (modificate per essere gestite dal flag -p)
PROXY="" # Memorizza l'indirizzo del proxy se fornito (es. socks5://127.0.0.1:9050)
PROXY_ARG="" # Memorizza l'argomento proxy per i tool che usano -proxy

s_flag=false # flag for search subdomains
m_flag=false # flag for use mapper
b_flag=false # flag for blind XSS
p_flag=false # flag for use proxy (NEW!)

usage() {
  echo -e "Use -i for IP/CIDR or -d for file with domains\n -a for active scan (optional)\n -s for enable subdomain search with domain\n -b for enable blind XSS\n -m for enable misconfig-mapper\n -p for use proxy (e.g. socks5://127.0.0.1:9050)" 1>&2
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
    wp=wordpress.txt
    response=$dir_name
    js=$dir_name/js
    log=$dir_name/log.log
    dns_result=$dir_name/scope/dns_ptr.txt  # domain retrived from IP
    scans=$dir_name/scans
    scope=$dir_name/scope
    nmap=$dir_name/nmap

    # crea file resolver default se non esiste (sicuro e non tocca /etc)
    if [ ! -f "$dir_name/$RESOLVERS_FILENAME" ]; then
        cat > "$dir_name/$RESOLVERS_FILENAME" <<EOF
1.1.1.1
8.8.8.8
9.9.9.9
EOF
        echo -e "${YELLOW}[!] Created default resolver list at ${CYAN}$dir_name/$RESOLVERS_FILENAME${NC}"
    fi
}

# -------------------------
# Funzioni DNS-safe
# -------------------------

# throttled_dnsx: esegue httpx + dnsx in modalità 'rate-limited' per evitare di saturare il resolver locale.
# Uso: throttled_dnsx input_list output_file
throttled_dnsx() {
    local input_list="$1"
    local out="$2"
    local tmp_hosts
    tmp_hosts=$(mktemp)

    # Prendi hosts via httpx per normalizzare URL (se input è lista di url/domains)
    # Non fallire se httpx non è installato — fallback a cat
    if command -v httpx >/dev/null 2>&1; then
        # USA PROXY_ARG
        sort -u "$input_list" | httpx $PROXY_ARG -silent > "$tmp_hosts"
    else
        sort -u "$input_list" > "$tmp_hosts"
    fi

    # split in chunk per evitare di lanciare mille processi tutti insieme
    split_prefix="$dir_name/dns_chunk_"
    split -l $DNS_CHUNK_SIZE "$tmp_hosts" "$split_prefix"

    # processa ogni chunk con xargs limitando concorrenza, poi pausa breve
    for chunk in ${split_prefix}*; do
        [ -f "$chunk" ] || continue
        # ogni riga -> una chiamata dnsx, concorrente fino a DNS_CONCURRENCY (xargs -P)
        # usiamo bash -c così usiamo la variabile risolutori locale
        RESOLVERS="$dir_name/$RESOLVERS_FILENAME" OUT="$out" \
        cat "$chunk" | xargs -n1 -P $DNS_CONCURRENCY -I{} bash -c \
        'echo "{}" | dnsx -silent -a -resp -r "$RESOLVERS" >> "$OUT" 2>/dev/null || true'
        # pausa tra i batch
        sleep $DNS_PAUSE
    done

    # cleanup
    rm -f ${split_prefix}* "$tmp_hosts" 2>/dev/null || true
}

# safe_ptr: esegue PTR (reverse) in modo sicuro (unica chiamata, con resolver dedicato)
safe_ptr() {
    local ip="$1"
    local out="$2"
    local resolvers="$dir_name/$RESOLVERS_FILENAME"
    # chiamata singola, non parallela
    echo "$ip" | dnsx -silent -resp-only -ptr -r "$resolvers" >> "$out" 2>> $log || true
}

# -------------------------
# Funzioni pre-esistenti (con piccole sostituzioni dove usavano dnsx direttamente)
# -------------------------

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
        # usa httpx + dnsx ma tramite throttled_dnsx per non sovraccaricare resolver
        # assumiamo che $1 sia una lista di hosts/urls
        throttled_dnsx "$1" "$result_tmp"

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
        rm -f $result_tmp
     else
        local valid_domains=()
        while IFS= read -r line; do
            valid_domains+=("$line")
        done <  "$dir_name/$domain"

        while IFS= read -r domain_value; do
            found=false
            for valid_domain in "${valid_domains[@]}"; do
                if [[ "$domain_value" == *"$valid_domain" || "$domain_value" == "$valid_domain" || "$domain_value" == *."$valid_domain" ]]; then
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

    # usa httpx normalmente (questo non fa molte query DNS), ma mantiene output
    if command -v httpx >/dev/null 2>&1; then
        # USA PROXY_ARG
        httpx $PROXY_ARG -l $targets --silent  -srd $response > $live_target 2>> $log
    else
        # fallback semplice: prende i targets così come sono
        cp -f "$targets" "$live_target" 2>> $log || true
    fi
    echo -e "${GREEN}[+] Scope checked${NC}"
}

nmap_check(){
    local nmap_result=$dir_name/nmap/all
    echo -e "${YELLOW}[-] Start NMAP enumeration${NC}"
    nmap -sC -sV $ip -oA $nmap_result 1>>/dev/null 2>>$log || true
    if [ -f "$nmap/all.nmap" ]; then
      cat $nmap/all.nmap | grep -o 'DNS:[^,]*' | awk -F: '{print $2}'  | sort | uniq > $dns_result
    fi
    echo -e "${GREEN}[+] NMAP enumeration completed. Result saved in:${NC} ${CYAN}$nmap_result${NC}"
}

dns_enum() {
    echo -e "${YELLOW}[-] Start DNS enumeration${NC}"
    local resolvers="$dir_name/$RESOLVERS_FILENAME"
    # safe_ptr: usa il resolver dedicato
    safe_ptr "$ip" "$dns_result"
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
        mkdir -p "$scans/${url#*//}"
        # USA PROXY_ARG
        katana $PROXY_ARG -silent -u $url  -d 5 -jc -kf all -fx -xhr -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg > $result_katana 2>> $log || true
        # USA PROXY_ARG
        urlfinder $PROXY_ARG -silent -d $url >> $result_katana 2>> $log || true
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

     # launch tools in background but they non dovrebbero sovraccaricare il resolver
     assetfinder --subs-only < "$dns_result" | grep -v "[INF]" > $sub1 2>> $log &
     findomain -q -f $dns_result > $sub2 2>> $log &
     subfinder -dL $dns_result -silent -all -nc > $sub3 2>> $log &
     wait

     echo -e "${YELLOW}[-] Merge of subdomains${NC}"
     cat $sub1 $sub2 $sub3 | alterx --silent -en >> $tmp 2>>$log || true

     sort -u $tmp > $subdomains
     rm -f $tmp $dir_name/subdomains-*

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

        # USA PROXY_ARG
        katana $PROXY_ARG --silent -f qurl -iqp -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -u "$url" -fx > "$targets_local"
        
        # paramspider usa --proxy
        local paramspider_proxy=""
        if [[ -n "$PROXY" ]]; then
            paramspider_proxy="--proxy $PROXY"
        fi
        paramspider $paramspider_proxy -d ${url#*://} 1>/dev/null 2>> $log || true
        
        if [ -d "$results" ] && [ "$(ls -A $results/ 2>/dev/null)" ]; then
            cat $results/* >> $scans/${url#*//}/$targets_url
            rm -rf $results
        fi
        echo -e "${YELLOW}[+] Parameters discover completed for ${NC}${CYAN}$url${NC}${YELLOW}.Results saved in:${NC}${CYAN}$scans/${url#*//}/$targets_url${NC}"
    done < "$live_target"
    echo -e "${GREEN}[+] Parameters discover completed for live targets."${NC}
}

nuclei_check() {
     echo -e "${YELLOW}[-] Start enumeration with Nuclei for live targets${NC}"
     # USA PROXY_ARG
     nuclei $PROXY_ARG  --silent -ut >/dev/null 2>>$log || true
     while IFS= read -r url; do
        echo -e "${YELLOW}[-] Start enumeration for:${NC}${CYAN}$url${NC}"
        # USA PROXY_ARG
        nuclei $PROXY_ARG --silent -fr -t technologies -u "$url"  -nc > $scans/${url#*//}/$technologies 2>>$log || true
        # USA PROXY_ARG
        nuclei $PROXY_ARG --silent -fr -t cves -u "$url"  -nc > $scans/${url#*//}/$cves 2>>$log || true
        # USA PROXY_ARG
        nuclei $PROXY_ARG --silent -fr -id http-missing-security-headers -u "$url" -nc > $scans/${url#*//}/$nuclei_headers 2>>$log || true
        # USA PROXY_ARG
        nuclei $PROXY_ARG --silent -fr -t takeovers -u "$url" -nc > $scans/${url#*//}/$takeover 2>>$log || true
        # USA PROXY_ARG
        nuclei $PROXY_ARG --silent -fr -t github/topscoder/nuclei-wordfence-cve  -u "$url" -nc > $scans/${url#*//}/$wp 2>>$log || true
        echo -e "${YELLOW}[+] Nuclei enumeration completed for ${CYAN}$url${NC}.${YELLOW}\nResults saved in:${NC}${CYAN}\n$scans/${url#*//}/$technologies\n$scans/${url#*//}/$cves\n$scans/${url#*//}/$nuclei_vuln\n${CYAN}$scans/${url#*//}/$takeover\n$scans/${url#*//}/$nuclei_headers\n${NC}"
    done < "$live_target"
    echo -e "${GREEN}[+] Nuclei enumeration completed.${NC}"
}

dalfox_check(){
    echo -e "${YELLOW}[-] Start XSS check with Dalfox for valid url${NC}"
    for target in $(ls $scans);do
        if [[ -s $scans/$target/$targets_url ]]; then
        echo -e "${YELLOW}[-] Start XSS check with Dalfox for ${NC}${CYAN}$target${NC}"
        # dalfox usa --proxy
        local dalfox_proxy=""
        if [[ -n "$PROXY" ]]; then
            dalfox_proxy="--proxy $PROXY"
        fi
        dalfox file $scans/$target/$targets_url $dalfox_proxy --remote-payloads=portswigger,payloadbox --waf-evasion > $scans/$target/$dalfox_out 2> $scans/$target/$dalfox_log || true
        echo -e "${GREEN}[+] XSS completed. Results saved in:${NC}${CYAN}$dalfox_out${NC}"
    	# ############################### TEST BLIND XSS ############################### #
            if [[ "${b_flag}" = true ]]; then
                echo -e "${YELLOW}[-] Start XSS Blind check with Dalfox for $target${NC}"
                interactsh-client -v -sf $scans/$target/$interact_session > $scans/$target/$interact_output 2>&1 &
                sleep 10
                local remote=$(cat $scans/$target/$interact_output| sed -r 's/\x1B\[[0-9;]*[mK]//g' | grep "\[INF\]" | awk 'NR==3' | cut -d " "  -f 2)
                echo $remote
                remote="http://$remote"
                echo $remote
                dalfox file $scans/$target/$targets_url $dalfox_proxy --waf-evasion -b $remote > $dalfox_blind_out 2>> $dalfox_log || true
                echo -e "${GREEN}[+] XSS Blind completed. Results saved in:${NC}${CYAN}$scans/$target/$dalfox_blind${NC}"
            fi
        # ############################### TEST BLIND XSS ############################### #
        else
            echo -e "${YELLOW}[-] Not valid urls found. Dalfox check skipped for${NC}${CYAN}$target${NC}"
        fi
    done
}

secret_check(){
    echo -e "${YELLOW}[-] Start secrets finding for live targets${NC}"
    for dir in $(ls $scans);do
        echo -e "${YELLOW}[-] Start secrets finding for: ${NC}${CYAN}$dir${NC}"
        local temp=$scans/$dir/temp.tmp
        # USA PROXY_ARG
        katana $PROXY_ARG -u $scans/$dir/$katana_result --silent -em js -d 5 -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg > $temp || true
        sort -u $temp > $scans/$dir/$statics
        echo "" > $temp

        for i in $(cat $scans/$dir/$katana_result);do
            python "$(pipx runpip LinkFinder show LinkFinder | awk -F ': ' '/Location/ {print $2 "/linkfinder.py"}')" -i $i -d -o cli | grep -a -v "Running against" | grep -a -v "^$" | grep -a -v "Invalid input defined or SSL error for:" | grep -a -v "Usage" >>  $temp 2>>$log || true
        done

        sort -u $temp | grep -ivf clear-list.txt > $scans/$dir/$link || true
        echo "" > $temp

        if [[ -s  $scans/$dir/$statics ]]; then
            mkdir -p $scans/$dir/findings
            c=1
            
            # secretfinder usa --proxy
            local sf_proxy=""
            if [[ -n "$PROXY" ]]; then
                sf_proxy="--proxy $PROXY"
            fi

            for i in $(cat  $scans/$dir/$statics);do
                if curl -s $i | grep -q "//# sourceMappingURL=data:application/json;charset=utf-8;base64"; then
                    echo "${YELLOW}Secretfinder for ${NC}${CYAN}$i${NC}${YELLOW}skipped. The content could block its execution. Manual execution with ${NC}${CYAN}secretfinder -i $i -g 'jquery;bootstrap;api.google.com' -o cli > $scans/$dir/findings/$c.txt${NC}"
                else
                    # USA sf_proxy
                    secretfinder $sf_proxy -i $i -g 'jquery;bootstrap;api.google.com' -o cli > $scans/$dir/findings/$c.txt || true
                fi
                ((c=c+1))
            done

            cat  $scans/$dir/findings/* >> $temp 2>/dev/null || true
            sort -u $temp > $scans/$dir/findings/$findings || true
                echo -e "${YELLOW}[+] Secret findings for ${CYAN}$dir${NC}${YELLOW} completed. Results saved in the directory ${NC}${CYAN}$scans/$dir/findings/ ${NC}${YELLOW} unique result saved in: ${NC}${CYAN}$scans/$dir/findings/$findings${NC}"
            else
                echo -e "${YELLOW}[-] Statics not found for ${CYAN}$dir${NC}${YELLOW} SecretFinder skipped${NC}"
            fi
        rm -f "$temp"
        echo -e "${YELLOW}[-] Start secrets finding with nuclei for ${CYAN}$dir${NC}"
        # USA PROXY_ARG
        nuclei $PROXY_ARG -t javascript/enumeration -nc -u $dir --silent > $scans/$dir/$nuclei_findings 2>>$log || true
        if [[ -n "$domain" ]];then
            # USA PROXY_ARG
            nuclei $PROXY_ARG -t JSA -nc  -u $dir --silent | grep "PII" | grep -v "\"\""  >> $scans/$dir/$nuclei_findings || true
        else
            # USA PROXY_ARG
            nuclei $PROXY_ARG -t JSA -u -nc $dir --silent | grep "PII" | grep -v "\"\""  >> $scans/$dir/$nuclei_findings || true
        fi
        echo -e "${GREEN}[+] Secret findings completed for ${CYAN}$dir${NC}.${GREEN} Results saved in:${NC}${CYAN}$scans/$dir/$nuclei_findings${NC} ${GREEN}and${NC} ${CYAN}$scans/$dir/$link${NC}"

    done
        echo -e "${GREEN}[+] Secret findings for live targets${NC}${YELLOW}completed${NC}"

}

dir_search() {
    echo -e "${YELLOW}[-] Start directory enumeration${NC}"
    if [ -n "$domain" ];then
        if [[ "$s_flag" = false ]]; then
            # USA PROXY_ARG
            httpx $PROXY_ARG -l $targets --silent -srd $response > $live_target
        fi
    fi

    while IFS= read -r url; do
        # dirsearch usa --proxy
        local ds_proxy=""
        if [[ -n "$PROXY" ]]; then
            ds_proxy="--proxy $PROXY"
        fi
        dirsearch $ds_proxy -u "$url" --log "$scans/${url#*//}/dirsearch_log.txt" --crawl -r -q -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json -O plain -o "$scans/${url#*//}/$dirsearch" 1>/dev/null 2>/dev/null || true
        echo -e "${GREEN}[+] Directory enumeration completed for ${NC}${CYAN}$url${NC}.${GREEN}Results saved in:${NC}${CYAN}$scans/${url#*//}/$dirsearch${NC}"
    done < "$live_target"
    echo -e "${GREEN}[+] Directory enumeration completed."
}

screenshot() {
    echo -e "${YELLOW}[-] Take screenshots ${NC}"
    mkdir -p $dir_name/screenshot
    if [ -n "$ip" ]; then
        gowitness scan nmap -f $dir_name/nmap/all.xml -o --screenshot-fullpage --write-db -q 2>>$log || true
    fi
    gowitness scan file -f $live_target --screenshot-fullpage --write-db  -q 2>>$log || true

    mv -f gowitness.sqlite3 $dir_name/screenshot/ 2>/dev/null || true

    echo -e "${GREEN}[+] Screenshot taken. Results saved in:${NC}${CYAN}$dir_name/screenshot${NC}\n${YELLOW}Run ${CYAN}gowitness report server${NC}${YELLOW} for check the report${NC}"
}

mapper() {
    echo -e "${YELLOW}[-] Mapping vulnerabilities ${NC}"
    # USA PROXY_ARG con httpx
    awk -F'.' '{print $(NF-1)}' $(cat $target | httpx $PROXY_ARG --silent ) | sort | uniq > $domains
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
        # USA PROXY_ARG
        httpx $PROXY_ARG -l "$domain" --silent -srd "$response" > $live_target
    fi

    if [[ -s "$live_target" ]]; then
        echo -e "${YELLOW}[-] Generazione file targets da live_target${NC}"
        cat "$live_target" | awk -F/ '{print $3}' | sort -u > "$targets"
        echo -e "${GREEN}[+] File targets creato:${NC} ${CYAN}$targets${NC}"
    else
        echo -e "${RED}[!] Nessun target vivo trovato con httpx${NC}"
    fi

    statics_enum
    screenshot
    secret_check
}

while getopts ":i:d:asmbp:" options; do
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
    p) # NEW: Gestione del proxy
        p_flag=true
        PROXY=${OPTARG}
        # Imposta l'argomento standard per la maggior parte dei tool (es. httpx, katana, nuclei)
        PROXY_ARG="-proxy $PROXY" 
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

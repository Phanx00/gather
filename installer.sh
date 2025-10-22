go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
sudo mv ~/go/bin/nuclei /usr/local/bin/
go install github.com/projectdiscovery/katana/cmd/katana@latest
sudo mv ~/go/bin/katana /usr/local/bin/
go install github.com/hahwul/dalfox/v2@latest
sudo mv ~/go/bin/dalfox /usr/local/bin/
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo mv ~/go/bin/httpx /usr/local/bin/
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
sudo mv ~/go/bin/dnsx /usr/local/bin/
go install github.com/tomnomnom/assetfinder@latest
sudo mv ~/go/bin/assetfinder /usr/local/bin/
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
sudo mv ~/go/bin/subfinder /usr/local/bin/
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
sudo mv ~/go/bin/interactsh-client /usr/local/bin/
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
sudo mv ~/go/bin/alterx /usr/local/bin/
go install github.com/sensepost/gowitness@latest
sudo mv ~/go/bin/gowitness /usr/local/bin/
go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
sudo mv ~/go/bin/urlfinder /usr/local/bin/



curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/local/bin/findomain
sudo rm findomain-linux.zip

pipx ensurepath 

# pipx install git+https://github.com/devanshbatham/ParamSpider.git not work
git clone https://github.com/devanshbatham/ParamSpider.git 
cd ParamSpider
pipx install .
cd .

#pipx install git+https://github.com/maurosoria/dirsearch.git 
pipx install git+https://github.com/GerbenJavado/LinkFinder.git --include-deps   
pipx install git+https://github.com/angelopassaro/SecretFinder --include-deps



wget https://raw.githubusercontent.com/w9w/JSA/main/templates/credentials-disclosure-all.yaml
wget https://raw.githubusercontent.com/w9w/JSA/main/templates/some-PIIs.yaml
nuclei -silent
mkdir ~/nuclei-templates/JSA
mv some-PIIs.yaml ~/nuclei-templates/JSA/
mv credentials-disclosure-all.yaml ~/nuclei-templates/JSA/

sudo apt install dirsearch -y 

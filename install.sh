#!/bin/bash
################################################################################
# Original Author: Oakey22
# Maintained by: Coolguy3289
# Version 1.99 (April 2021)
#
# Program:
#   Install Lbry Pool on Ubuntu 18.04 running Nginx, MariaDB, and php7.x
################################################################################

output() {
  printf "\E[0;33;40m"
  echo "$1"
  printf "\E[0m"
}

displayErr() {
  echo
  echo "$1"
  echo
  exit 1
}

################################################################################
# Main routine
################################################################################

# Capture all output in a log file
LOG_FILE="${0%.sh}.log"
{
  echo "-----------------------------------------------------------------------"
  echo "LBRY Pool install log of" "$(date)"
  echo "Use less -R to view without control characters."
  echo "-----------------------------------------------------------------------"
  echo
} >"${LOG_FILE}"
exec &> >(tee -a "${LOG_FILE}")

# Phase 0: Ask user to enter configuration data ################################
clear
output "LBRY Pool Installer"
output ""
output "Make sure you double check before hitting enter! Only one shot at these!"
output ""

# Load file with last configuration data if available
CONF_FILE="${0%.sh}.conf"
if [[ -f "${CONF_FILE}" ]]; then
  # shellcheck source=install.conf
  source "${CONF_FILE}"
else
  declare -A CONFMAP=(["TIME_ZONE"]="" ["SERVER_NAME"]="" ["SUB_DOMAIN"]="" ["EMAIL"]="" ['SEND_EMAIL']=""
    ["BTC"]="" ["ADMIN_PANEL"]="" ["PUBLIC_IP"]="" ["INSTALL_FAIL2BAN"]="" ["UFW"]="" ["SSL_INSTALL"]="")
fi
# Ask user to enter/change configuration data
read -e -r -p "Enter time zone (e.g. America/New_York): " -i "${CONFMAP['TIME_ZONE']}" CONFMAP['TIME_ZONE']
read -e -r -p "Server name (no http:// or www. just example.com): " -i "${CONFMAP['SERVER_NAME']}" CONFMAP['SERVER_NAME']
read -e -r -p "Are you using a subdomain (e.g. pool.example.com?) [y/N] : " -i "${CONFMAP['SUB_DOMAIN']}" CONFMAP['SUB_DOMAIN']
read -e -r -p "Enter support email (e.g. admin@example.com) : " -i "${CONFMAP['EMAIL']}" CONFMAP['EMAIL']
read -e -r -p "Send a test email to the support address? [Y/n] : " -i "${CONFMAP['SEND_EMAIL']}" CONFMAP['SEND_EMAIL']
read -e -r -p "Set stratum to AutoExchange? i.e. mine any coin with BTC address? [y/N] : " -i "${CONFMAP['BTC']}" CONFMAP['BTC']
read -e -r -p "Please enter a new location for /site/adminRights this is to customize the admin entrance url (e.g. myAdminpanel) : " -i "${CONFMAP['ADMIN_PANEL']}" CONFMAP['ADMIN_PANEL']
read -e -r -p "Enter your Public IP for admin access (http://www.whatsmyip.org/) : " -i "${CONFMAP['PUBLIC_IP']}" CONFMAP['PUBLIC_IP']
read -e -r -p "Install Fail2ban? [Y/n] : " -i "${CONFMAP['INSTALL_FAIL2BAN']}" CONFMAP['INSTALL_FAIL2BAN']
read -e -r -p "Install UFW and configure ports? [Y/n] : " -i "${CONFMAP['UFW']}" CONFMAP['UFW']
read -e -r -p "Install LetsEncrypt SSL? IMPORTANT! You MUST have your domain name pointed to this server prior to running the script!! [Y/n]: " -i "${CONFMAP['SSL_INSTALL']}" CONFMAP['SSL_INSTALL']
# Save configuration data to file
declare -p CONFMAP >"${CONF_FILE}"

# Phase 1: Install dependencies ################################################
clear
output "LBRY Pool Installer"
output ""
output "Updating system and installing required packages."
output ""

# 1.a: Update packages and upgrade Ubuntu
output "... updating system through apt"
sudo apt update
sudo apt upgrade -y
sudo apt autoremove -y
output ""
output "... removing Snapd, and Cloud-Init (Ubuntu 18.x+)"
sudo snap stop lxc && sudo snap remove lxc
sudo snap stop core18 && sudo snap remove core18
sudo snap remove snapd
sudo apt purge -y snapd*
sudo apt purge cloud-init*
sudo rm -rf /etc/cloud
sudo apt autoremove -y

# 1.b: Install all dependencies
clear
output "Installing MySQL repository."
output ""
wget https://dev.mysql.com/get/mysql-apt-config_0.8.17-1_all.deb
sudo dpkg -i ./mysql-apt-config_0.8.17-1_all.deb
sudo apt update
export DEBIAN_FRONTEND="noninteractive"
output "Installing pre-requisite repositories."
output ""
sudo apt install software-properties-common -y
sudo add-apt-repository ppa:ondrej/php -y
sudo add-apt-repository ppa:bitcoin/bitcoin -y
sudo apt update
output "Installing Required Software."
output ""
sudo apt install nginx mysql-server php7.4-opcache php7.4-fpm php7.4-common php7.4-gd php7.4-mysql php7.4-imap php7.4-cli php7.4-cgi php7.4-curl php7.4-intl php7.4-pspell recode php7.4-sqlite3 php7.4-tidy php7.4-xmlrpc php7.4-xsl php7.4-memcache php7.4-imagick php7.4-zip php7.4-mbstring php-pear php-auth-sasl mcrypt imagemagick libruby memcached libgmp3-dev libmysqlclient-dev libcurl4-gnutls-dev libkrb5-dev libldap2-dev libidn11-dev gnutls-dev librtmp-dev build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils sendmail git pwgen unzip libdb4.8-dev libdb4.8++-dev libssl-dev libboost-all-dev libminiupnpc-dev libqt5gui5 libqt5core5a libqt5webkit5-dev libqt5dbus5 qttools5-dev qttools5-dev-tools libprotobuf-dev protobuf-compiler libqrencode-dev libnghttp2-dev libpsl-dev tmux -y
output "Configuring Nginx server."
output ""
sudo rm -f /etc/nginx/sites-enabled/default
sudo service nginx start
sudo service cron start
# Making Nginx a bit hard
# shellcheck disable=SC2016
echo 'map $http_user_agent $blockedagent {
default         0;
~*malicious     1;
~*bot           1;
~*backdoor      1;
~*crawler       1;
~*bandit        1;
}
' | sudo -E tee /etc/nginx/blockuseragents.rules >/dev/null 2>&1

# 1.c: Check email
output "Testing to see if server emails are sent."
output ""
if [[ "${CONFMAP['EMAIL']}" != "" ]]; then
  echo "${CONFMAP['EMAIL']}" >~/.email
  echo "${CONFMAP['EMAIL']}" >~/.forward

  if [[ ("${CONFMAP['SEND_EMAIL']}" == "y" || "${CONFMAP['SEND_EMAIL']}" == "Y" || "${CONFMAP['SEND_EMAIL']}" == "") ]]; then
    {
      echo "Subject: SMTP Test Mail"
      echo "This is a mail test for the SMTP Service."
      echo "You should receive this !"
      echo
      echo "Cheers"
      echo
    } >/tmp/email.message
    # shellcheck disable=SC2024
    sudo sendmail "${CONFMAP['EMAIL']}" </tmp/email.message
    rm -f /tmp/email.message
    echo "Mail sent"
  fi
fi

# 1.d: Optional installs
output "Some optional installs"
if [[ ("${CONFMAP['INSTALL_FAIL2BAN']}" == "y" || "${CONFMAP['INSTALL_FAIL2BAN']}" == "Y" || "${CONFMAP['INSTALL_FAIL2BAN']}" == "") ]]; then
  sudo apt install fail2ban -y
fi
if [[ ("${CONFMAP['UFW']}" == "y" || "${CONFMAP['UFW']}" == "Y" || "${CONFMAP['UFW']}" == "") ]]; then
  sudo apt-get install ufw -y
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw allow ssh
  sudo ufw allow http
  sudo ufw allow https
  sudo ufw allow 3334/tcp
  sudo ufw --force enable
fi

# Phase 2: YIIMP ###############################################################
clear
output " Installing yiimp"
output ""
output "Grabbing yiimp from Github, building files and setting file structure."
output ""
cd ~ || exit
git clone https://github.com/lbryio/pool.git yiimp

# 2.a: Build blocknotify
# Generating Random Password for stratum (to be used blocknotify and stratum config further down)
BLCKNOTIFYPASS=$(pwgen -cn 32 1)
cd "${HOME}"/yiimp/blocknotify || exit
sudo sed -i 's/tu8tu5/'"${BLCKNOTIFYPASS}"'/' blocknotify.cpp
sudo make

# 2.b: Build iniparser
cd "${HOME}"/yiimp/stratum/iniparser || exit
sudo make

# 2.c: Build stratum
cd "${HOME}"/yiimp/stratum || exit
if [[ ("${CONFMAP['BTC']}" == "y" || "${CONFMAP['BTC']}" == "Y") ]]; then
  # If exchange to BTC is desired, remove the NO_EXCHANGE macro definition
  sudo sed -i 's/CFLAGS += -DNO_EXCHANGE/#CFLAGS += -DNO_EXCHANGE/' "${HOME}"/yiimp/stratum/Makefile
  sudo make
fi
sudo make

# 2.d: Compose yiimp runtime environment
cd "${HOME}"/yiimp || exit
sudo sed -i 's/AdminRights/'"${CONFMAP['ADMIN_PANEL']}"'/' "${HOME}"/yiimp/web/yaamp/modules/site/SiteController.php
sudo cp -r "${HOME}"/yiimp/web /var/
sudo mkdir -p /var/stratum
cd "${HOME}"/yiimp/stratum || exit
sudo cp -a config.sample/. /var/stratum/config
sudo cp -r stratum /var/stratum
sudo cp -r run.sh /var/stratum
cd "${HOME}"/yiimp || exit
sudo cp -r "${HOME}"/yiimp/bin/. /usr/bin/
# sudo cp -r $HOME/yiimp/blocknotify/blocknotify /var/stratum
sudo cp -r "${HOME}"/yiimp/blocknotify/blocknotify /usr/bin
sudo mkdir -p /etc/yiimp
sudo mkdir -p "${HOME}"/backup/
#fixing yiimp
sudo sed -i "s|ROOTDIR=/data/yiimp|ROOTDIR=/var/yiimp|g" /usr/bin/yiimp
#fixing run.sh
sudo rm -r /var/stratum/config/run.sh
# shellcheck disable=SC2016
echo '
#!/bin/bash
ulimit -n 10240
ulimit -u 10240
cd /var/stratum
while true; do
        ./stratum /var/stratum/config/$1
        sleep 2
done
exec bash
' | sudo -E tee /var/stratum/config/run.sh >/dev/null 2>&1
sudo chmod +x /var/stratum/config/run.sh
output "Update default timezone."
output "Thanks for using this installation script. Donations welcome"
# check if link file
sudo [ -L /etc/localtime ] && sudo unlink /etc/localtime
# update time zone
sudo ln -sf /usr/share/zoneinfo/"${CONFMAP['TIME_ZONE']}" /etc/localtime
sudo apt install -y ntpdate
# write time to clock if possible
sudo hwclock -w

# Phase 3: Web Server configuration ############################################
clear
output "Making Web Server Magic Happen!"
# adding user to group, creating dir structure, setting permissions
sudo mkdir -p /var/www/"${CONFMAP['SERVER_NAME']}"/html
output "Creating webserver initial config file"
output ""
if [[ ("${CONFMAP['SUB_DOMAIN']}" == "y" || "${CONFMAP['SUB_DOMAIN']}" == "Y") ]]; then
  # shellcheck disable=SC2016
  echo 'include /etc/nginx/blockuseragents.rules;
	server {
	if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
        listen 80;
        listen [::]:80;
        server_name '"${CONFMAP['SERVER_NAME']}"';
        root "/var/www/'"${CONFMAP['SERVER_NAME']}"'/html/web";
        index index.html index.htm index.php;
        charset utf-8;
    
        location / {
        try_files $uri $uri/ /index.php?$args;
        }
        location @rewrite {
        rewrite ^/(.*)$ /index.php?r=$1;
        }
    
        location = /favicon.ico { access_log off; log_not_found off; }
        location = /robots.txt  { access_log off; log_not_found off; }
    
        access_log off;
        error_log  /var/log/nginx/'"${CONFMAP['SERVER_NAME']}"'.app-error.log error;
    
        # allow larger file uploads and longer script runtimes
        client_body_buffer_size  50k;
        client_header_buffer_size 50k;
        client_max_body_size 50k;
        large_client_header_buffers 2 50k;
        sendfile off;
    
        location ~ ^/index\.php$ {
            fastcgi_split_path_info ^(.+\.php)(/.+)$;
            fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
            fastcgi_index index.php;
            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_intercept_errors off;
            fastcgi_buffer_size 16k;
            fastcgi_buffers 4 16k;
            fastcgi_connect_timeout 300;
            fastcgi_send_timeout 300;
            fastcgi_read_timeout 300;
	    try_files $uri $uri/ =404;
        }
		location ~ \.php$ {
        	return 404;
        }
		location ~ \.sh {
		return 404;
        }
		location ~ /\.ht {
		deny all;
        }
		location ~ /.well-known {
		allow all;
        }
		location /phpmyadmin {
  		root /usr/share/;
  		index index.php;
  		try_files $uri $uri/ =404;
  		location ~ ^/phpmyadmin/(doc|sql|setup)/ {
    		deny all;
  	}
  		location ~ /phpmyadmin/(.+\.php)$ {
    		fastcgi_pass unix:/run/php/php7.4-fpm.sock;
    		fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    		include fastcgi_params;
    		include snippets/fastcgi-php.conf;
  	}
 }
 }
' | sudo -E tee /etc/nginx/sites-available/"${CONFMAP['SERVER_NAME']}".conf >/dev/null 2>&1

  sudo ln -s /etc/nginx/sites-available/"${CONFMAP['SERVER_NAME']}".conf /etc/nginx/sites-enabled/"${CONFMAP['SERVER_NAME']}".conf
  sudo ln -s /var/web /var/www/"${CONFMAP['SERVER_NAME']}"/html
  sudo service nginx restart
  if [[ ("${CONFMAP['SSL_INSTALL']}" == "y" || "${CONFMAP['SSL_INSTALL']}" == "Y" || "${CONFMAP['SSL_INSTALL']}" == "") ]]; then
    output "Install LetsEncrypt and setting SSL"
    sudo apt install software-properties-common
    sudo add-apt-repository universe
    sudo add-apt-repository ppa:certbot/certbot
    sudo apt update
    sudo apt install -y certbot python-certbot-nginx
    sudo certbot certonly -a webroot --webroot-path=/var/web --email "${CONFMAP['EMAIL']}" --agree-tos -d "${CONFMAP['SERVER_NAME']}"
    sudo rm /etc/nginx/sites-available/"${CONFMAP['SERVER_NAME']}".conf
    sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
    # I am SSL Man!
    # shellcheck disable=SC2016
    echo 'include /etc/nginx/blockuseragents.rules;
	server {
	if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
        listen 80;
        listen [::]:80;
        server_name '"${CONFMAP['SERVER_NAME']}"';
    	# enforce https
        return 301 https://'"${CONFMAP['SERVER_NAME']}"'$request_uri;
	}
	
	server {
	if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
            listen 443 ssl http2;
            listen [::]:443 ssl http2;
            server_name '"${CONFMAP['SERVER_NAME']}"';
        
            root /var/www/'"${CONFMAP['SERVER_NAME']}"'/html/web;
            index index.php;
        
            access_log /var/log/nginx/'"${CONFMAP['SERVER_NAME']}"'.app-accress.log;
            error_log  /var/log/nginx/'"${CONFMAP['SERVER_NAME']}"'.app-error.log error;
        
            # allow larger file uploads and longer script runtimes
        client_body_buffer_size  50k;
        client_header_buffer_size 50k;
        client_max_body_size 50k;
        large_client_header_buffers 2 50k;
        sendfile off;
        
            # strengthen ssl security
            ssl_certificate /etc/letsencrypt/live/'"${CONFMAP['SERVER_NAME']}"'/fullchain.pem;
            ssl_certificate_key /etc/letsencrypt/live/'"${CONFMAP['SERVER_NAME']}"'/privkey.pem;
            ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
            ssl_prefer_server_ciphers on;
            ssl_session_cache shared:SSL:10m;
            ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:ECDHE-RSA-AES128-GCM-SHA256:AES256+EECDH:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";
            ssl_dhparam /etc/ssl/certs/dhparam.pem;
        
            # Add headers to serve security related headers
            add_header Strict-Transport-Security "max-age=15768000; preload;";
            add_header X-Content-Type-Options nosniff;
            add_header X-XSS-Protection "1; mode=block";
            add_header X-Robots-Tag none;
            add_header Content-Security-Policy "frame-ancestors '"'"'self'"'"';
        
        location / {
        try_files $uri $uri/ /index.php?$args;
        }
        location @rewrite {
        rewrite ^/(.*)$ /index.php?r=$1;
        }
    
        
            location ~ ^/index\.php$ {
                fastcgi_split_path_info ^(.+\.php)(/.+)$;
                fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
                fastcgi_index index.php;
                include fastcgi_params;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                fastcgi_intercept_errors off;
                fastcgi_buffer_size 16k;
                fastcgi_buffers 4 16k;
                fastcgi_connect_timeout 300;
                fastcgi_send_timeout 300;
                fastcgi_read_timeout 300;
                include /etc/nginx/fastcgi_params;
	    	try_files $uri $uri/ =404;
        }
		location ~ \.php$ {
        	return 404;
        }
		location ~ \.sh {
		return 404;
        }
        
            location ~ /\.ht {
                deny all;
            }
	    location /phpmyadmin {
  		root /usr/share/;
  		index index.php;
  		try_files $uri $uri/ =404;
  		location ~ ^/phpmyadmin/(doc|sql|setup)/ {
    		deny all;
  	}
  		location ~ /phpmyadmin/(.+\.php)$ {
    		fastcgi_pass unix:/run/php/php7.4-fpm.sock;
    		fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    		include fastcgi_params;
    		include snippets/fastcgi-php.conf;
  	}
 }
 }
        
' | sudo -E tee /etc/nginx/sites-available/"${CONFMAP['SERVER_NAME']}".conf >/dev/null 2>&1
  fi
  sudo service nginx restart
  sudo service php7.4-fpm reload
else
  # shellcheck disable=SC2016
  echo 'include /etc/nginx/blockuseragents.rules;
	server {
	if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
        listen 80;
        listen [::]:80;
        server_name '"${CONFMAP['SERVER_NAME']}"' www.'"${CONFMAP['SERVER_NAME']}"';
        root "/var/www/'"${CONFMAP['SERVER_NAME']}"'/html/web";
        index index.html index.htm index.php;
        charset utf-8;
    
        location / {
        try_files $uri $uri/ /index.php?$args;
        }
        location @rewrite {
        rewrite ^/(.*)$ /index.php?r=$1;
        }
    
        location = /favicon.ico { access_log off; log_not_found off; }
        location = /robots.txt  { access_log off; log_not_found off; }
    
        access_log off;
        error_log  /var/log/nginx/'"${CONFMAP['SERVER_NAME']}"'.app-error.log error;
    
        # allow larger file uploads and longer script runtimes
 	client_body_buffer_size  50k;
        client_header_buffer_size 50k;
        client_max_body_size 50k;
        large_client_header_buffers 2 50k;
        sendfile off;
    
        location ~ ^/index\.php$ {
            fastcgi_split_path_info ^(.+\.php)(/.+)$;
            fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
            fastcgi_index index.php;
            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_intercept_errors off;
            fastcgi_buffer_size 16k;
            fastcgi_buffers 4 16k;
            fastcgi_connect_timeout 300;
            fastcgi_send_timeout 300;
            fastcgi_read_timeout 300;
	    try_files $uri $uri/ =404;
        }
		location ~ \.php$ {
        	return 404;
        }
		location ~ \.sh {
		return 404;
        }
		location ~ /\.ht {
		deny all;
        }
		location ~ /.well-known {
		allow all;
        }
		location /phpmyadmin {
  		root /usr/share/;
  		index index.php;
  		try_files $uri $uri/ =404;
  		location ~ ^/phpmyadmin/(doc|sql|setup)/ {
    		deny all;
  	}
  		location ~ /phpmyadmin/(.+\.php)$ {
    		fastcgi_pass unix:/run/php/php7.4-fpm.sock;
    		fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    		include fastcgi_params;
    		include snippets/fastcgi-php.conf;
  	}
 }
 }
' | sudo -E tee /etc/nginx/sites-available/"${CONFMAP['SERVER_NAME']}".conf >/dev/null 2>&1

  sudo ln -s /etc/nginx/sites-available/"${CONFMAP['SERVER_NAME']}".conf /etc/nginx/sites-enabled/"${CONFMAP['SERVER_NAME']}".conf
  sudo ln -s /var/web /var/www/"${CONFMAP['SERVER_NAME']}"/html
  sudo service nginx restart
  if [[ ("${CONFMAP['SSL_INSTALL']}" == "y" || "${CONFMAP['SSL_INSTALL']}" == "Y" || "${CONFMAP['SSL_INSTALL']}" == "") ]]; then
    output "Install LetsEncrypt and setting SSL"
    sudo apt install software-properties-common
    sudo add-apt-repository universe
    sudo add-apt-repository ppa:certbot/certbot
    sudo apt update
    sudo apt install -y certbot python-certbot-nginx
    sudo certbot certonly -a webroot --webroot-path=/var/web --email "${CONFMAP['EMAIL']}" --agree-tos -d "${CONFMAP['SERVER_NAME']}" -d www."${CONFMAP['SERVER_NAME']}"
    sudo rm /etc/nginx/sites-available/"${CONFMAP['SERVER_NAME']}".conf
    sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
    # I am SSL Man!
    # shellcheck disable=SC2016
    echo 'include /etc/nginx/blockuseragents.rules;
	server {
	if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
        listen 80;
        listen [::]:80;
        server_name '"${CONFMAP['SERVER_NAME']}"';
    	# enforce https
        return 301 https://'"${CONFMAP['SERVER_NAME']}"'$request_uri;
	}
	
	server {
	if ($blockedagent) {
                return 403;
        }
        if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 444;
        }
            listen 443 ssl http2;
            listen [::]:443 ssl http2;
            server_name '"${CONFMAP['SERVER_NAME']}"' www.'"${CONFMAP['SERVER_NAME']}"';
        
            root /var/www/'"${CONFMAP['SERVER_NAME']}"'/html/web;
            index index.php;
        
            access_log /var/log/nginx/'"${CONFMAP['SERVER_NAME']}"'.app-accress.log;
            error_log  /var/log/nginx/'"${CONFMAP['SERVER_NAME']}"'.app-error.log error;
        
            # allow larger file uploads and longer script runtimes
 	client_body_buffer_size  50k;
        client_header_buffer_size 50k;
        client_max_body_size 50k;
        large_client_header_buffers 2 50k;
        sendfile off;
        
            # strengthen ssl security
            ssl_certificate /etc/letsencrypt/live/'"${CONFMAP['SERVER_NAME']}"'/fullchain.pem;
            ssl_certificate_key /etc/letsencrypt/live/'"${CONFMAP['SERVER_NAME']}"'/privkey.pem;
            ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
            ssl_prefer_server_ciphers on;
            ssl_session_cache shared:SSL:10m;
            ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:ECDHE-RSA-AES128-GCM-SHA256:AES256+EECDH:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";
            ssl_dhparam /etc/ssl/certs/dhparam.pem;
        
            # Add headers to serve security related headers
            add_header Strict-Transport-Security "max-age=15768000; preload;";
            add_header X-Content-Type-Options nosniff;
            add_header X-XSS-Protection "1; mode=block";
            add_header X-Robots-Tag none;
            add_header Content-Security-Policy "frame-ancestors '"'"'self'"'"'";
        
        location / {
        try_files $uri $uri/ /index.php?$args;
        }
        location @rewrite {
        rewrite ^/(.*)$ /index.php?r=$1;
        }
    
        
            location ~ ^/index\.php$ {
                fastcgi_split_path_info ^(.+\.php)(/.+)$;
                fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
                fastcgi_index index.php;
                include fastcgi_params;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                fastcgi_intercept_errors off;
                fastcgi_buffer_size 16k;
                fastcgi_buffers 4 16k;
                fastcgi_connect_timeout 300;
                fastcgi_send_timeout 300;
                fastcgi_read_timeout 300;
                include /etc/nginx/fastcgi_params;
	    	try_files $uri $uri/ =404;
        }
		location ~ \.php$ {
        	return 404;
        }
		location ~ \.sh {
		return 404;
        }
        
            location ~ /\.ht {
                deny all;
            }
	    location /phpmyadmin {
  		root /usr/share/;
  		index index.php;
  		try_files $uri $uri/ =404;
  		location ~ ^/phpmyadmin/(doc|sql|setup)/ {
    		deny all;
  	}
  		location ~ /phpmyadmin/(.+\.php)$ {
    		fastcgi_pass unix:/run/php/php7.4-fpm.sock;
    		fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    		include fastcgi_params;
    		include snippets/fastcgi-php.conf;
  	}
 }
 }
        
' | sudo -E tee /etc/nginx/sites-available/"${CONFMAP['SERVER_NAME']}".conf >/dev/null 2>&1
  fi
  sudo service nginx restart
  sudo service php7.4-fpm reload
fi

# Phase 4: Database configuration ##############################################
clear
output "Now for the database fun!"
# Generate passwords for MySQL
MYSQL_ROOTPASSWD=$(pwgen -cn 20 1)
MYSQL_PANELPASSWD=$(pwgen -cn 20 1)
MYSQL_STRATUMPASSWD=$(pwgen -cn 20 1)
MYSQL_PHPADMINPASSWD=$(pwgen -cn 20 1)
# create database
Q1="CREATE DATABASE IF NOT EXISTS yiimpfrontend;"
Q2="CREATE USER 'panel'@'localhost' IDENTIFIED BY '${MYSQL_PANELPASSWD}';"
Q3="GRANT ALL ON *.* TO 'panel'@'localhost';"
Q4="FLUSH PRIVILEGES;"
SQL="${Q1}${Q2}${Q3}${Q4}"
sudo mysql -u root -p="" -e "$SQL"
# create stratum user
Q1="CREATE USER 'stratum'@'localhost' IDENTIFIED BY '${MYSQL_STRATUMPASSWD}';"
Q2="GRANT ALL ON *.* TO 'stratum'@'localhost';"
Q3="FLUSH PRIVILEGES;"
SQL="${Q1}${Q2}${Q3}"
sudo mysql -u root -p="" -e "$SQL"

#Create my.cnf

echo '
[clienthost1]
user=panel
password='"${MYSQL_PANELPASSWD}"'
database=yiimpfrontend
host=localhost
[clienthost2]
user=stratum
password='"${MYSQL_STRATUMPASSWD}"'
database=yiimpfrontend
host=localhost
[mysql]
user=root
password='"${MYSQL_ROOTPASSWD}"'
[myphpadmin]
user=root
password='"${MYSQL_PHPADMINPASSWD}"'
' | sudo -E tee ~/.my.cnf >/dev/null 2>&1
sudo chmod 0600 ~/.my.cnf

#Create keys file
echo '  
    <?php
/* Sample config file to put in /etc/yiimp/keys.php */
define('"'"'YIIMP_MYSQLDUMP_USER'"'"', '"'"'panel'"'"');
define('"'"'YIIMP_MYSQLDUMP_PASS'"'"', '"'"''"${MYSQL_PANELPASSWD}"''"'"');
/* Keys required to create/cancel orders and access your balances/deposit addresses */
define('"'"'EXCH_BITTREX_SECRET'"'"', '"'"'<my_bittrex_api_secret_key>'"'"');
define('"'"'EXCH_BITSTAMP_SECRET'"'"','"'"''"'"');
define('"'"'EXCH_BLEUTRADE_SECRET'"'"', '"'"''"'"');
define('"'"'EXCH_BTER_SECRET'"'"', '"'"''"'"');
define('"'"'EXCH_CCEX_SECRET'"'"', '"'"''"'"');
define('"'"'EXCH_COINMARKETS_PASS'"'"', '"'"''"'"');
define('"'"'EXCH_CRYPTOPIA_SECRET'"'"', '"'"''"'"');
define('"'"'EXCH_EMPOEX_SECKEY'"'"', '"'"''"'"');
define('"'"'EXCH_HITBTC_SECRET'"'"', '"'"''"'"');
define('"'"'EXCH_KRAKEN_SECRET'"'"','"'"''"'"');
define('"'"'EXCH_LIVECOIN_SECRET'"'"', '"'"''"'"');
define('"'"'EXCH_NOVA_SECRET'"'"','"'"''"'"');
define('"'"'EXCH_POLONIEX_SECRET'"'"', '"'"''"'"');
define('"'"'EXCH_YOBIT_SECRET'"'"', '"'"''"'"');
' | sudo -E tee /etc/yiimp/keys.php >/dev/null 2>&1

output "Peforming the SQL import"
output ""
cd ~ || exit
cd yiimp/sql || exit
# import sql dump
sudo zcat 2016-04-03-yaamp.sql.gz | sudo mysql --defaults-group-suffix=host1
# oh the humanity!
sudo mysql --defaults-group-suffix=host1 --force <2016-04-24-market_history.sql
sudo mysql --defaults-group-suffix=host1 --force <2016-04-27-settings.sql
sudo mysql --defaults-group-suffix=host1 --force <2016-05-11-coins.sql
sudo mysql --defaults-group-suffix=host1 --force <2016-05-15-benchmarks.sql
sudo mysql --defaults-group-suffix=host1 --force <2016-05-23-bookmarks.sql
sudo mysql --defaults-group-suffix=host1 --force <2016-06-01-notifications.sql
sudo mysql --defaults-group-suffix=host1 --force <2016-06-04-bench_chips.sql
sudo mysql --defaults-group-suffix=host1 --force <2016-11-23-coins.sql
sudo mysql --defaults-group-suffix=host1 --force <2017-02-05-benchmarks.sql
sudo mysql --defaults-group-suffix=host1 --force <2017-03-31-earnings_index.sql
sudo mysql --defaults-group-suffix=host1 --force <2017-05-accounts_case_swaptime.sql
sudo mysql --defaults-group-suffix=host1 --force <2017-06-payouts_coinid_memo.sql
sudo mysql --defaults-group-suffix=host1 --force <2017-09-notifications.sql
sudo mysql --defaults-group-suffix=host1 --force <2017-11-segwit.sql
sudo mysql --defaults-group-suffix=host1 --force <2018-01-stratums_ports.sql
sudo mysql --defaults-group-suffix=host1 --force <2018-02-coins_getinfo.sql
clear
output "Generating a basic serverconfig.php"
output ""
# make config file
# shellcheck disable=SC2016
echo '
<?php
ini_set('"'"'date.timezone'"'"', '"'"'UTC'"'"');
define('"'"'YAAMP_LOGS'"'"', '"'"'/var/log'"'"');
define('"'"'YAAMP_HTDOCS'"'"', '"'"'/var/web'"'"');
define('"'"'YAAMP_BIN'"'"', '"'"'/var/bin'"'"');
define('"'"'YAAMP_DBHOST'"'"', '"'"'localhost'"'"');
define('"'"'YAAMP_DBNAME'"'"', '"'"'yiimpfrontend'"'"');
define('"'"'YAAMP_DBUSER'"'"', '"'"'panel'"'"');
define('"'"'YAAMP_DBPASSWORD'"'"', '"'"''"${MYSQL_PANELPASSWD}"''"'"');
define('"'"'YAAMP_PRODUCTION'"'"', true);
define('"'"'YAAMP_RENTAL'"'"', false);
define('"'"'YAAMP_LIMIT_ESTIMATE'"'"', false);
define('"'"'YAAMP_FEES_MINING'"'"', 0.5);
define('"'"'YAAMP_FEES_EXCHANGE'"'"', 2);
define('"'"'YAAMP_FEES_RENTING'"'"', 2);
define('"'"'YAAMP_TXFEE_RENTING_WD'"'"', 0.002);
define('"'"'YAAMP_PAYMENTS_FREQ'"'"', 3*60*60);
define('"'"'YAAMP_PAYMENTS_MINI'"'"', 0.001);
define('"'"'YAAMP_ALLOW_EXCHANGE'"'"', false);
define('"'"'YIIMP_PUBLIC_EXPLORER'"'"', true);
define('"'"'YIIMP_PUBLIC_BENCHMARK'"'"', true);
define('"'"'YIIMP_FIAT_ALTERNATIVE'"'"', '"'"'USD'"'"'); // USD is main
define('"'"'YAAMP_USE_NICEHASH_API'"'"', false);
define('"'"'YAAMP_BTCADDRESS'"'"', '"'"'1NMDeanjyad2gcpumbZmF13fMLqDKNxxQ5'"'"');
define('"'"'YAAMP_SITE_URL'"'"', '"'"''"${CONFMAP['SERVER_NAME']}"''"'"');
define('"'"'YAAMP_STRATUM_URL'"'"', YAAMP_SITE_URL); // change if your stratum server is on a different host
define('"'"'YAAMP_SITE_NAME'"'"', '"'"'Crypto'"'"');
define('"'"'YAAMP_ADMIN_EMAIL'"'"', '"'"''"${CONFMAP['EMAIL']}"''"'"');
define('"'"'YAAMP_ADMIN_IP'"'"', '"'"''"${CONFMAP['PUBLIC_IP']}"''"'"'); // samples: "80.236.118.26,90.234.221.11" or "10.0.0.1/8"
define('"'"'YAAMP_ADMIN_WEBCONSOLE'"'"', true);
define('"'"'YAAMP_NOTIFY_NEW_COINS'"'"', false);
define('"'"'YAAMP_DEFAULT_ALGO'"'"', '"'"'lbry'"'"');
define('"'"'YAAMP_USE_NGINX'"'"', true);
// Exchange public keys (private keys are in a separate config file)
define('"'"'EXCH_CRYPTOPIA_KEY'"'"', '"'"''"'"');
define('"'"'EXCH_POLONIEX_KEY'"'"', '"'"''"'"');
define('"'"'EXCH_BITTREX_KEY'"'"', '"'"''"'"');
define('"'"'EXCH_BLEUTRADE_KEY'"'"', '"'"''"'"');
define('"'"'EXCH_BTER_KEY'"'"', '"'"''"'"');
define('"'"'EXCH_YOBIT_KEY'"'"', '"'"''"'"');
define('"'"'EXCH_CCEX_KEY'"'"', '"'"''"'"');
define('"'"'EXCH_COINMARKETS_USER'"'"', '"'"''"'"');
define('"'"'EXCH_COINMARKETS_PIN'"'"', '"'"''"'"');
define('"'"'EXCH_BITSTAMP_ID'"'"','"'"''"'"');
define('"'"'EXCH_BITSTAMP_KEY'"'"','"'"''"'"');
define('"'"'EXCH_HITBTC_KEY'"'"','"'"''"'"');
define('"'"'EXCH_KRAKEN_KEY'"'"', '"'"''"'"');
define('"'"'EXCH_LIVECOIN_KEY'"'"', '"'"''"'"');
define('"'"'EXCH_NOVA_KEY'"'"', '"'"''"'"');
// Automatic withdraw to Yaamp btc wallet if btc balance > 0.3
define('"'"'EXCH_AUTO_WITHDRAW'"'"', 0.3);
// nicehash keys deposit account & amount to deposit at a time
define('"'"'NICEHASH_API_KEY'"'"','"'"''"'"');
define('"'"'NICEHASH_API_ID'"'"','"'"''"'"');
define('"'"'NICEHASH_DEPOSIT'"'"','"'"''"'"');
define('"'"'NICEHASH_DEPOSIT_AMOUNT'"'"','"'"''"'"');
$cold_wallet_table = array(
	'"'"'1NMDeanjyad2gcpumbZmF13fMLqDKNxxQ5'"'"' => 0.10,
);
// Sample fixed pool fees
$configFixedPoolFees = array(
        '"'"'zr5'"'"' => 2.0,
        '"'"'scrypt'"'"' => 20.0,
        '"'"'sha256'"'"' => 5.0,
);
// Sample custom stratum ports
$configCustomPorts = array(
//	'"'"'x11'"'"' => 7000,
);
// mBTC Coefs per algo (default is 1.0)
$configAlgoNormCoef = array(
//	'"'"'x11'"'"' => 5.0,
);
' | sudo -E tee /var/web/serverconfig.php >/dev/null 2>&1

output "Adding tmux start file to ~/"
# shellcheck disable=SC2016
echo '
#!/bin/bash
LOG_DIR=/var/log
WEB_DIR=/var/web
STRATUM_DIR=/var/stratum
USR_BIN=/usr/bin
tmux new -d -s main bash $WEB_DIR/main.sh
tmux new -d -s loop2 bash $WEB_DIR/loop2.sh
tmux new -d -s blocks bash $WEB_DIR/blocks.sh
tmux new -d -s debug tail -f $LOG_DIR/debug.log
tmux new -d -s stratum bash $STRATUM_DIR/run.sh lbry
' | sudo -E tee ~/pool-start.sh >/dev/null 2>&1
sudo chmod +x ~/pool-start.sh

# Old screen commands:
# screen -dmS main bash $WEB_DIR/main.sh
# screen -dmS loop2 bash $WEB_DIR/loop2.sh
# screen -dmS blocks bash $WEB_DIR/blocks.sh
# screen -dmS debug tail -f $LOG_DIR/debug.log
# screen -dmS stratum bash $STRATUM_DIR/run.sh lbry

output "Updating stratum config files with database connection info."
output ""
cd /var/stratum/config || exit
sudo sed -i 's/password = tu8tu5/password = '"${BLCKNOTIFYPASS}"'/g' ./*.conf
sudo sed -i 's/server = yaamp.com/server = '"${CONFMAP['SERVER_NAME']}"'/g' ./*.conf
sudo sed -i 's/host = yaampdb/host = localhost/g' ./*.conf
sudo sed -i 's/database = yaamp/database = yiimpfrontend/g' ./*.conf
sudo sed -i 's/username = root/username = stratum/g' ./*.conf
sudo sed -i 's/password = patofpaq/password = '"${MYSQL_STRATUMPASSWD}"'/g' ./*.conf
cd ~ || exit

sudo rm -rf "${HOME}"/yiimp
sudo service nginx restart
sudo service php7.3-fpm reload
cd ~ || exit
wget https://github.com/lbryio/lbrycrd/releases/download/v0.17.3.3/lbrycrd-linux-1733.zip
sudo unzip lbrycrd-linux-1733.zip -d /usr/bin

# Make sure the working area of the lbrycrdd does exist by starting the daemon for some seconds
if [[ ! -d ~/.lbrycrd ]]; then
  lbrycrdd -daemon -server
  sleep 3
  lbrycrd-cli stop
fi

# Create config for Lbry
echo && echo "Configuring Lbrycrd.conf"
sleep 3
RPCUSER=$(pwgen -cn 32 1)
RPCPASSWORD=$(pwgen -cn 32 1)
echo '
rpcuser='"${RPCUSER}"'
rpcpassword='"${RPCPASSWORD}"'
rpcport=14390
rpcthreads=24
rpcallowip=127.0.0.1
# onlynet=ipv4
maxconnections=36
daemon=1
server=1
deprecatedrpc=accounts
gen=0
alertnotify=echo %s | mail -s "LBRY Credits alert!" '"${CONFMAP['EMAIL']}"'
blocknotify=blocknotify 127.0.0.1:3334 1439 %s
' | sudo -E tee ~/.lbrycrd/lbrycrd.conf
sleep 3

output "Final Directory permissions"
output ""
WHOAMI=$(whoami)
sudo usermod -aG www-data "${WHOAMI}"
sudo mkdir /root/backup/
sudo mkdir /var/yiimp
sudo ln -s /var/web /var/yiimp/web
sudo chown -R www-data:www-data /var/stratum
sudo chown -R www-data:www-data /var/web
sudo chown -R www-data:www-data /var/yiimp
sudo chmod -R 775 /var/www/"${CONFMAP['SERVER_NAME']}"/html
sudo chmod -R 775 /var/web
sudo chmod -R 775 /var/yiimp
sudo chmod -R 775 /var/stratum
sudo chmod -R 775 /var/web/yaamp/runtime
sudo chmod -R 775 /root/backup/
sudo chmod -R 775 /var/log
sudo chmod -R 775 /var/web/serverconfig.php
sudo chmod a+w /var/web/yaamp/runtime
sudo chmod a+w /var/log
sudo chmod a+w /var/web/assets

lbrycrdd -daemon -server

clear
output "Your mysql information is saved in ~/.my.cnf"
output ""
output "Please login to the admin panel at http://${CONFMAP['SERVER_NAME']}/site/${CONFMAP['ADMIN_PANEL']}"
output ""
output "Your RPC username is ${RPCUSER}"
output "Your RPC Password is ${RPCPASSWORD}"

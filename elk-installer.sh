#!/bin/bash
########################################################################################################
# Instalador automatizado Kit ELK - Kibana + Filebeat + ElasticSearch rodando NGINX como proxy reverso #
# Autor: Guilherme Silva Martins																	   #
# Filebeat coleta os logs provenientes do syslog e gera visualização dos logs dos servicos e do nginx  #
# no Kibana 																						   #
########################################################################################################

logfile='/home/agm_logs/instalador-elk.log'
dirInstall='/usr/src/elk'
DIRBACKUP='/home/agm_logs/'
IP=`hostname -I | cut -d' ' -f1`

function LOG(){
	echo "[`date \"+%d-%m-%Y %H:%M:%S:%s\"`] [ELK Installer] - $1" >> $logfile
}

function installPkgs(){
	LOG "Realizando update dos pacotes e instalação de pacotes necessários	"
	apt-get -y update && apt-get -y upgrade && apt-get -y install software-properties-common liblognorm5 default-jdk default-jre curl wget net-tools apache2-utils sudo git libjson-glib-1.0-0:amd64 libjson-glib-1.0-common zip apt-transport-https cowsay
	
	LOG "Criando diretório para downloads e instalação de pacotes"
	mkdir $dirInstall

}

function is_root_user() {
	if [[ $EUID != 0 ]]; then
    	return 1
  	fi
  	return 0
}

function BACKUPDIR(){
	if [ -e $DIRBACKUP ]; then
	        LOG "Diretorio de backup ja existe"
	else
	        LOG "Criando diretório de backup"
	        mkdir -p $DIRBACKUP
	fi
}

function installElastic(){
	versionES='elasticsearch-7.3.0-amd64.deb'
	linkElastic='https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.3.0-amd64.deb'
	dirConfig='/etc/elasticsearch/elasticsearch.yml'
	
	LOG "Alterando para o diretório de instalação"
	cd $dirInstall

	LOG "Realizando Download e instalando $versionES"
	wget -c $linkElastic && dpkg -i $versionES

	LOG "Iniciando ElasticSearch"
	systemctl daemon-reload
	systemctl enable elasticsearch.service
	systemctl start elasticsearch.service

	if [ $? -eq 0 ]; then
		echo "Instalação do ElasticSearch concluida com sucesso!"
		LOG "Instalação ElasticSearch concluida com sucesso!"

		LOG "Realizando ajustes na configuração"
		#echo "network.host: $IP" >> $dirConfig

		LOG "Elastic - Network OK"
		echo "network.host: localhost" >> $dirConfig
		#sed -i "s/#network.host: 192.168.0.1/network.host: \$IP/g" $dirConfig
		
		LOG "Elastic - Porta OK"
		sed -i "s/#http.port/http.port/g" $dirConfig
		#echo "discovery.seed_hosts: $IP" >> $dirConfig
		#echo "discovery.seed_hosts: localhost" >> $dirConfig
		
		#Habilitar quando o certificado SSL gerado for válido
		LOG "Elastic - Ajustando xPack"
		echo -e "xpack.security.enabled: true
#xpack.security.http.ssl.enabled: true
#xpack.security.transport.ssl.enabled: true
#xpack.security.http.ssl.key: certs/ca.key
#xpack.security.http.ssl.certificate: certs/ca.crt
#xpack.security.http.ssl.certificate_authorities: certs/ca.crt
#xpack.security.transport.ssl.key: certs/ca.key
#xpack.security.transport.ssl.certificate: certs/ca.crt
#xpack.security.transport.ssl.certificate_authorities: certs/ca.crt" >> $dirConfig

		LOG "Reiniciando ElasticSearch"
		/etc/init.d/elasticsearch restart

	else
		echo "Erro na instalação do ElasticSearch"
		LOG "Erro na instalação do ElasticSearch"
	fi
}

function configFirewall(){
		iptables -I INPUT -p tcp -d $IP --dport 9200 -j DROP ; iptables -I INPUT -p tcp -s $IP --dport 9200 -j ACCEPT
}

function installFileBeat(){
	versionFB='filebeat-7.3.0-amd64.deb'
	linkFB='https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.3.0-amd64.deb'
	configFileFB='/etc/filebeat/filebeat.yml'

	LOG "Realizando o download do $versionFB..."
	echo -e "Realizando o download do $versionFB..."
	wget -c $linkFB

	LOG "Instalando filebeat!"
	dpkg -i $versionFB

	if [ $? -eq 0 ]; then
		echo "Instalação do FileBeat concluida com sucesso!"
		LOG "Instalação do FileBeat concluida com sucesso!"

		LOG "Incluindo FileBeat na inicialização"
		systemctl daemon-reload
		systemctl enable filebeat.service

		LOG "Realizando ajustes no arquivo de configuração $configFileFB"
		cp $configFileFB{,.bak}
		sed -i 's/#host:/host:/g' $configFileFB
		sed -i "s/localhost:5601/$IP:5601/g" $configFileFB
		sed -i 's/#password:/password:/g' $configFileFB
		sed -i 's/changeme/qwe123/g' $configFileFB
		sed -i 's/#username/username/g' $configFileFB

		LOG "Iniciando Filebeat"
	  	systemctl start filebeat.service

	  	sleep 5

	 	LOG "Habilitando módulos System e Nginx do Filebeat"
	  	filebeat modules enable system nginx
	  	filebeat setup
	  	systemctl start filebeat.service

  	else
		echo "Erro na instalação do FileBeat"
		LOG "Erro na instalação do FileBeat"
	fi

}

function installLogstash(){
	#Logstash não esta sendo utilizado na atual infraestrutura, porém pode ser necessário futuramente
	versionLS='logstash-7.3.0.deb'
	linkLogstash='https://artifacts.elastic.co/downloads/logstash/logstash-7.3.0.deb'
	configLogstash='/etc/logstash/conf.d/logstash.conf'
	newConfigFile='/etc/logstash/conf.d/10-syslog.conf'

	LOG "Alterando para o diretório de instalação"
	cd $dirInstall

	LOG "Download $versionLS ..."
	wget -c $linkLogstash

	LOG "Instalando LogStash"
	dpkg -i $versionLS

	if [ $? -eq 0 ]; then
		echo -e "Instalação do LogStash concluida com sucesso!"
		LOG "Instalação do LogStash concluida com sucesso!"
	fi
	
	if [ -e $configLogstash ]; then
		LOG "Arquivo de configuração ja existe, movendo para backup"
		mv $configLogstash{,.bak}

		echo -e "input {
		 beats {
		   port => 5044
		   ssl => true
		   ssl_certificate => \"/etc/ssl/logstash-forwarder.crt\"
		   ssl_key => \"/etc/ssl/logstash-forwarder.key.pem\"
		  }
		}

		filter {
		if [type] == \"syslog\" {
		    grok {
		      match => { \"message" => "%{SYSLOGLINE}\" }
		    }
		 
		date {
		match => [ \"timestamp\", \"MMM  d HH:mm:ss\", \"MMM dd HH:mm:ss\" ]
		}
		  }
		 
		}

		output {
		 elasticsearch {
		  hosts => localhost
		    index => \"%{[@metadata][beat]}-%{+YYYY.MM.dd}\"
		       }
		stdout {
		    codec => rubydebug
		       }
		}" >> $configLogstash


		LOG "Iniciando LogStash"
		systemctl daemon-reload
		systemctl enable logstash.service
		systemctl start logstash.service

	else
		echo -e "Erro na instalação do LogStash"
		LOG "Erro na instalação do LogStash"
	fi
}

function installKibana(){
	versionK='kibana-7.3.0-amd64.deb'
	linkKibana='https://artifacts.elastic.co/downloads/kibana/kibana-7.3.0-amd64.deb'
	configFilek='/etc/kibana/kibana.yml'

	LOG "Alterando para o diretório de instalação"
	cd $dirInstall

	LOG "Download $versionK ..."
	wget -c $linkKibana

	LOG "Instalando Kibana"
	dpkg -i $versionK

	if [ $? -eq 0 ]; then

		echo "Instalação do Kibana concluida com sucesso!"
		LOG "Instalação do Kibana concluida com sucesso!"

		LOG "Realizando ajustes na configuração do Kibana"
		sed -i "s/#server.port:/server.port:/g" $configFilek
		LOG "Port OK"

		sed -i "s/#server.host:/server.host:/g" $configFilek
		LOG "Host OK"

		sed -i "s/"localhost"/$IP/g" $configFilek
		LOG "IP do Host OK"

		sed -i "s/#elasticsearch.hosts:/elasticsearch.hosts:/g" $configFilek
		LOG "Elastic host OK"

		sed -i "s#http://$IP:9200#http://localhost:9200#g" $configFilek
		LOG "Elastic IP OK"

		sed -i "s/#kibana.index/kibana.index/g" $configFilek
		LOG "Kibana Index OK"

		echo "xpack.security.enabled: true" >> $configFilek
		LOG "Habilitando xPack"

		sed -i 's/#elasticsearch.username/elasticsearch.username/g' $configFilek
		sed -i 's/#elasticsearch.password/elasticsearch.password/g' $configFilek
		LOG "Usuario e senha OK"

		LOG "Iniciando Kibana"
		/etc/init.d/kibana start
		systemctl enable kibana.service

		LOG "Ajustando usuários"
		/usr/share/elasticsearch/bin/elasticsearch-setup-passwords interactive

		sed -i "s/\"pass\"/\"qwe123\"/g" $configFilek
		LOG "Password OK"

		echo "Reiniciando Kibana"
		LOG "Reiniciando Kibana"
		/etc/init.d/kibana restart

	else

		echo "Erro na instalação do Kibana"
		LOG "Erro na instalação do Kibana"
	fi
}

function installNginx(){
	configNginx='/etc/nginx/sites-available/default'
	linkNginx='/etc/nginx/sites-enabled/default'
	keyCert='/etc/nginx/cert.key'
	crtCert='/etc/nginx/cert.crt'
	LOG "Instalando Nginx"
	apt-get -y update && apt-get -y install nginx nginx-common #nginx-full nginx-light nginx-extras

	if [ $? -eq 0 ]; then
		LOG "Nginx instalado com sucesso!"
		rm -f $configNginx

		LOG "Gerando certificado SSL para o NGINX, insira os dados solicitados"
		openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout $keyCert -out $crtCert

		LOG "Criando arquivo de configuração do NGINX"
		echo -e "server {
	    	listen 80;
	    	return 301 https://\$host\$request_uri;
		}
		 " >> $configNginx

		echo -e "server {
			listen 443;
			server_name elk;
		 

		  ssl_certificate           $crtCert;
		  ssl_certificate_key       $keyCert;
		 

		  ssl on;
		  ssl_session_cache  builtin:1000  shared:SSL:10m;
		  ssl_protocols  TLSv1 TLSv1.1 TLSv1.2;
			ssl_ciphers HIGH:!aNULL:!eNULL:!EXPORT:!CAMELLIA:!DES:!MD5:!PSK:!RC4;
		  ssl_prefer_server_ciphers on;
		 

		  access_log		/var/log/nginx/kibana.access.log;
		  error_log		/var/log/nginx/kibana.access.log;
		  #auth_basic 'Restricted Access';
		  #auth_basic_user_file /etc/nginx/htpasswd.users;
		 

		  location / {
		 

		  proxy_set_header        Host \$host;
		  proxy_set_header        X-Real-IP \$remote_addr;
		  proxy_set_header        X-Forwarded-For \$proxy_add_x_forwarded_for;
		  proxy_set_header        X-Forwarded-Proto \$scheme;
		 
		  # Fix the \"It appears that your reverse proxy set up is broken\" error.
		  proxy_pass          http://$IP:5601;
		  proxy_read_timeout  90;
		 
		  proxy_redirect      http://$IP:5601 https://$IP;
		  }
		}" >> $configNginx

		LOG "Criando link simbólico para sites-enable"
		ln -s $configNginx $linkNginx
		/etc/init.d/nginx restart

		#Senha será solicitada somente se configurar através do nginx, utilizando como proxy reverso
		#LOG "Definindo uma senha para acesso ao Kibana"
		#echo "Defina uma senha para acesar o Kibana via web"
		#htpasswd -c /etc/nginx/htpasswd.users kibanaadmin

	else
		LOG "Ocorreu algo estranho na instalação do Nginx, verifique"
	fi
}


function configRsyslog(){
	dirConfigRsys='/etc/rsyslog.d/00-elasticsearch.log'
	fileConfigSys='/etc/rsyslog.conf'

	LOG "Instalando pacote syslog-elasticsearch"
	apt-get -y install rsyslog-elasticsearch
	
	if [ -e $dirConfigRsys ]; then
		LOG "Arquivo de configuração $dirConfigRsys, movendo para backup"
		LOG "Configurando novo $dirConfigRsys"
		mv $dirConfigRsys{,.bak}
	fi

	LOG "Escrevendo novas configurações em $dirConfigRsys"
	echo -e "# BEGIN 
	module(load=\"omelasticsearch\")

	template(name=\"plain-syslog\" type=\"list\" option.json=\"on\") {
		constant(value=\"{\")
		constant(value=\"\\\"@timestamp\\\":\\\"\")     property(name=\"timereported\" dateFormat=\"rfc3339\")
		constant(value=\"\\\",\\\"host\\\":\\\"\")        property(name=\"hostname\")
		constant(value=\"\\\",\\\"severity-num\\\":\")  property(name=\"syslogseverity\")
		constant(value=\",\\\"facility-num\\\":\")    property(name=\"syslogfacility\")
		constant(value=\",\\\"severity\\\":\\\"\")      property(name=\"syslogseverity-text\")
		constant(value=\"\\\",\\\"facility\\\":\\\"\")    property(name=\"syslogfacility-text\")
		constant(value=\"\\\",\\\"syslogtag\\\":\\\"\")   property(name=\"syslogtag\")
		constant(value=\"\\\",\\\"message\\\":\\\"\")     property(name=\"msg\")
		constant(value=\"\\\"}\")
	}

	template(name=\"logstash-index\" type=\"string\" string=\"logstash-%\$YEAR%.%\$MONTH%.%\$DAY%\")

	action(type=\"omelasticsearch\"
	template=\"plain-syslog\"
	searchIndex=\"logstash-index\"
	dynSearchIndex=\"on\"
	bulkmode=\"on\"
	errorfile=\"/var/log/omelasticsearch.log\")" >> $dirConfigRsys

 	################ AJUSTE NO ARQUIVO DE CONFIGURAÇÃO DO RSYSLOG ##########################
	if [ -e $fileConfigSys ]; then
		LOG "Arquivo de configuração $fileConfigSys ja existe, movendo para backup"
		LOG "Configurando novo $fileConfigSys"
		mv $fileConfigSys{,.bak}
		> $fileConfigSys
	else
		LOG "Configurando $fileConfigSys"
		> $fileConfigSys
	fi

	echo -e "#/etc/rsyslog.conf	Configuration file for rsyslog *** EDITED TO WORK WITH ELK ***.
	#################
	#### MODULES ####
	################# 

	\$ModLoad imuxsock # provides support for local system logging
	\$ModLoad imklog   # provides kernel logging support
	#\$ModLoad immark  # provides --MARK-- message capability

	#provides UDP syslog reception
	\$ModLoad imudp
	\$UDPServerRun 514

	#provides TCP syslog reception
	\$ModLoad imtcp
	\$InputTCPServerRun 514

	###########################
	#### GLOBAL DIRECTIVES ####
	###########################

	#Use traditional timestamp format.
	\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

	#Set the default permissions for all log files.
	\$FileOwner root
	\$FileGroup adm
	\$FileCreateMode 0640
	\$DirCreateMode 0755
	\$Umask 0022

	#Where to place spool and state files
	\$WorkDirectory /var/spool/rsyslog
	 
	#Include all config files in /etc/rsyslog.d/	 
	\$IncludeConfig /etc/rsyslog.d/*.conf

	###############
	#### RULES ####
	###############	 
	#First some standard log files.  Log by facility.
	auth,authpriv.*			/var/log/auth.log
	*.*;auth,authpriv.none	-/var/log/syslog
	cron.*				 /home/agm_logs/cron.log
	daemon.*				-/var/log/daemon.log
	kern.*				-/var/log/kern.log
	lpr.*					-/var/log/lpr.log
	mail.*				-/var/log/mail.log
	user.*				-/var/log/user.log
	*.*				-/home/agm_logs/apache2/tomcat.log
	*.*				-/home/agm_bin/iPRV5/var/log/asterisk/iphone_recorder_agent_v5_full.log
	 
	#Logging for the mail system.	 
	mail.info			-/var/log/mail.info
	mail.warn			-/var/log/mail.warn
	mail.err			 /var/log/mail.err
	 
	#Some \"catch-all\" log files.	 
	*.=debug;\\ 
		auth,authpriv.none;\\ 
		news.none;mail.none	-/var/log/debug
	*.=info;*.=notice;*.=warn;\\ 
		auth,authpriv.none;\\ 
		cron,daemon.none;\\ 
		mail,news.none		-/var/log/messages
	 
	#Emergencies are sent to everybody logged in.	 
	*.emerg				:omusrmsg:*" >> $fileConfigSys

	LOG "Reiniciando rsyslog"
	/etc/init.d/rsyslog restart

	#Logstash necessita de ajuste nas permissões em alguns casos, verificar quando necessário
	#LOG "Ajustando permissoes dos arquivos de log"
	#chmod 644 /var/log/*.log
}

LOG "##################################"
LOG "## INICIANDO INSTALAÇÃO KIT ELK ##"
LOG "##################################"

if ! is_root_user; then
	echo "Você precisa ser root para executar a instalação!" 2>&1
	echo  2>&1
	exit 1
fi

######
BACKUPDIR

######
installPkgs

######
installElastic

######
configFirewall

######
#installLogstash
	
######
installKibana

######
configRsyslog

######
installNginx

######
installFileBeat

######

/usr/games/cowsay "#####	   ELK Instalado com sucesso		#######

 		Kibana: http://$IP
 		Usuario: elastic e senha definida
 		ElasticSearch http://$IP:9200
 		curl -XGET http://localhost:9200
 		curl -XGET http://localhost:9200    
 		Para visualizar os indexes use:
		http://localhost:9200/_cat/health?v 

		curl -u elastic:SENHADEFINIDA -XGET http://localhost:9200/_cat/indices?pretty

		Verifique a conexão com o ElasticSearch !!!!!"

#Remove pacote cowsay utilizado para exibição final :D
apt -y remove cowsay > /dev/null 2>&1
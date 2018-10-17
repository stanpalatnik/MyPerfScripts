mount hyd1filer1b:/vol/sata102/hydqa/ /mnt
PREFIX="/home/amazon/build/1532";
#rm -rf $PREFIX/*;
#PRECOMMAND="aclocal;automake --add-missing;autoconf";  # For Fedora
#PRECOMMAND="aclocal; automake --add-missing; autoconf; libtoolize";  #For UBUNTU

mkdir $PREFIX
#ver=14.04-tag-02
ver=15-tag-32
tag="15-tag-32.tgz"
tar -zxvf /mnt/internal_builds/n3fips/LiquidSecurity-NFBE/2.03/build_$ver/LiquidSecurity-NFBE-2.03-$tag;
cd LiquidSecurity-NFBE-2.03-$ver;

tar -zxvf CNL35XX-NFBE-API-2.03-$ver.tgz
tar -zxvf CNL35XX-NFBE-Cav-Client-2.03-$ver.tgz
tar -zxvf CNL35XX-NFBE-Cav-Client-Utils-2.03-$ver.tgz
tar -zxvf CNL35XX-NFBE-Cav-Management-Utils-2.03-$ver.tgz
tar -zxvf CNL35XX-NFBE-Cav-Server-2.03-$ver.tgz
tar -zxvf CNL35XX-NFBE-Linux-Driver-KVM-XEN-PF-2.03-$ver.tgz
tar -zxvf CNL35XX-NFBE-Linux-Driver-Utils-2.03-$ver.tgz
tar -zxvf CNL35XX-NFBE-PKCS11-2.03-$ver.tgz
tar -zxvf CNL35XX-NFBE-SSL-Engine-2.03-$ver.tgz

Main ()
{
	build_server_packages;
	#build_client_packages;
}

build_server_packages () 
{
	echo "*******BUILDING DRIVER***********"
	cd liquidsec_pf_vf_driver;
	make LIQUID_SECURITY_DIR=$PREFIX; make install LIQUID_SECURITY_DIR=$PREFIX;
	
	if [ $? == 0 ]
	then
	    echo "Compilation is successful"
	else
	    echo "Compilation failed !!! exit..."; exit;
	fi
	
	echo "***************************************"; echo "";sleep 5;
	
	echo "*******BUILDING API IOCTL***********"
	cd ../liquidsec_api/
	make distclean;
	#$PRECOMMAND;
	aclocal; automake --add-missing; autoconf; libtoolize;
	./configure --prefix=$PREFIX --enable-liquidsec_api_ioctl; make all; make install;
	
	if [ $? == 0 ]
	then
	    echo "Compilation is successful"
	else
	    echo "Compilation failed !!! exit..."; exit;
	fi
	echo "***************************************"; echo "";sleep 5;
	
	
	echo "*******BUILDING UTILS**********"
	cd ../liquidsec_utils/
	#$PRECOMMAND;
	aclocal; automake --add-missing; autoconf; libtoolize;
	./configure --prefix=$PREFIX --with-liquidsec_api_include_dir=$PREFIX/include/  --with-liquidsec_api_lib_dir=$PREFIX/lib/; make all; make install;
	
	if [ $? == 0 ]
	then
	    echo "Compilation is successful"
	else
	    echo "Compilation failed !!! exit..."; exit;
	fi
	echo "***************************************"; echo "";sleep 5;
	
	
	echo "*******BUILDING API SERVER**********"
	cd ../liquidsec_api/
	make distclean;
	#$PRECOMMAND;
	aclocal; automake --add-missing; autoconf; libtoolize;
	./configure --prefix=$PREFIX --enable-liquidsec_api_server --with-event_lib_dir=$PREFIX/lib/; make all; make install;
	
	if [ $? == 0 ]
	then
	    echo "Compilation is successful"
	else
	    echo "Compilation failed !!! exit..."; exit;
	fi
	echo "***************************************"; echo "";sleep 5;
	
	
	echo "*******BUILDING SERVER**********"
	cd ../liquidsec_cav_server;
	#$PRECOMMAND;
	aclocal; automake --add-missing; autoconf; libtoolize;
	./configure --prefix=$PREFIX --with-liquidsec_api_include_dir=$PREFIX/include/  --with-liquidsec_api_lib_dir=$PREFIX/lib/ --with-event_lib_dir=$PREFIX/lib/; make all; make install;
	
	if [ $? == 0 ]
	then
	    echo "Compilation is successful"
	else
	    echo "Compilation failed !!! exit..."; exit;
	fi
	echo "***************************************"; echo "";sleep 5;

	cd ../
}

build_client_packages ()
{

	echo "*******BUILDING API CLIENT**********"
	cd liquidsec_api/
	make distclean;
	echo $PRECOMMAND;
	#$PRECOMMAND;
	aclocal; automake --add-missing; autoconf; libtoolize;
	./configure --prefix=$PREFIX --enable-liquidsec_api_client; make all; make install;
	
	if [ $? == 0 ]
	then
	    echo "Compilation is successful"
	else
	    echo "Compilation failed !!! exit..."; exit;
	fi
	echo "***************************************"; echo "";sleep 5;
	
	
	echo "*******BUILDING CLIENT**********"
	cd ../liquidsec_cav_client;
	#$PRECOMMAND;
	aclocal; automake --add-missing; autoconf; libtoolize;
	./configure --prefix=$PREFIX --with-liquidsec_api_include_dir=$PREFIX/include/  --with-liquidsec_api_lib_dir=$PREFIX/lib/; make all; make install;
	
	if [ $? == 0 ]
	then
	    echo "Compilation is successful"
	else
	    echo "Compilation failed !!! exit..."; exit;
	fi
	echo "***************************************"; echo "";sleep 5;
	
	echo "*******BUILDING API MGMT UTILS**********"
	cd ../liquidsec_api/
	make distclean;
	#$PRECOMMAND;
	aclocal; automake --add-missing; autoconf; libtoolize;
	./configure --prefix=$PREFIX --enable-liquidsec_api_mgmt; make all; make install;
	
	if [ $? == 0 ]
	then
	    echo "Compilation is successful"
	else
	    echo "Compilation failed !!! exit..."; exit;
	fi
	echo "***************************************"; echo "";sleep 5;
	
	
	echo "*******BUILDING MGMT UTILS**********"
	cd ../liquidsec_cav_mgmt_utils;
	#$PRECOMMAND;
	aclocal; automake --add-missing; autoconf; libtoolize;
	./configure --prefix=$PREFIX --with-liquidsec_api_include_dir=$PREFIX/include/  --with-liquidsec_api_lib_dir=$PREFIX/lib/; make all; make install;
	
	if [ $? == 0 ]
	then
	    echo "Compilation is successful"
	else
	    echo "Compilation failed !!! exit..."; exit;
	fi
	echo "***************************************"; echo "";sleep 5;
	
	
	echo "*******BUILDING API SOCKET**********"
	cd ../liquidsec_api/
	make distclean;
	#$PRECOMMAND;
	aclocal; automake --add-missing; autoconf; libtoolize;
	./configure --prefix=$PREFIX --enable-liquidsec_api_socket; make all; make install;
	
	if [ $? == 0 ]
	then
	    echo "Compilation is successful"
	else
	    echo "Compilation failed !!! exit..."; exit;
	fi
	echo "***************************************"; echo "";sleep 5;
	
	echo "*******BUILDING CLIENT UTILS**********"
	cd ../liquidsec_cav_client_utils;
	#$PRECOMMAND;
	aclocal; automake --add-missing; autoconf; libtoolize;
	./configure --prefix=$PREFIX --with-liquidsec_api_include_dir=$PREFIX/include/  --with-liquidsec_api_lib_dir=$PREFIX/lib/; make all; make install;
	
	if [ $? == 0 ]
	then
	    echo "Compilation is successful"
	else
	    echo "Compilation failed !!! exit..."; exit;
	fi
	echo "***************************************"; echo "";sleep 5;
	
	
	echo "*******BUILDING SSL ENGINE**********"
	cd ../liquidsec_openssl_engine;
	#$PRECOMMAND;
	aclocal; automake --add-missing; autoconf; libtoolize;
	./configure --prefix=$PREFIX --with-liquidsec_api_include_dir=$PREFIX/include/  --with-liquidsec_api_lib_dir=$PREFIX/lib/; make all; make install;
	
	if [ $? == 0 ]
	then
	    echo "Compilation is successful"
	else
	    echo "Compilation failed !!! exit..."; exit;
	fi
	echo "***************************************"; echo "";sleep 5;
	
	echo "*******BUILDING PKCS11**********"
	cd ../liquidsec_pkcs11;
	#$PRECOMMAND;
	aclocal; automake --add-missing; autoconf; libtoolize;
	./configure --prefix=$PREFIX --with-liquidsec_api_include_dir=$PREFIX/include/  --with-liquidsec_api_lib_dir=$PREFIX/lib/; make all; make install;
	
	if [ $? == 0 ]
	then
	    echo "Compilation is successful"
	else
	    echo "Compilation failed !!! exit..."; exit;
	fi
	echo "***************************************"; echo "";sleep 5;
}

#Main ()
#{
#	build_server_packages;
#	build_client_packages;
#}

	Main;

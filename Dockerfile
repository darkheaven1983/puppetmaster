FROM centos:7
MAINTAINER darkheaven1983@gmail.com
RUN rpm -ivh http://yum.puppetlabs.com/puppetlabs-release-el-7.noarch.rpm
RUN yum -y install puppet-server hostname tar vim
CMD puppet master --verbose --no-daemonize
EXPOSE 8140

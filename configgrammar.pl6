#use Grammar::Tracer;

grammar Config {
  token ws {
    <ws-element>*
  }
  token ws-element {
    | \s+
    | \t+
    | \n+
    | '//' \N* \n
    | '#' \N* \n
  }
  rule TOP {
    [<statement> <.ws>]+
  }
  rule statement {
    | <acl>
    | <controls>
    | <include>
    | <key>
    | <logging>
    | <lwres>
    | <masters>
    | <options>
    | <server>
    | <statistics-channels>
    | <trusted-keys>
    | <managed-keys>
    | <view>
    | <zone>
  }
  rule acl {
    'acl' <acl-name> '{' <address-match-list> '}' ';'
  }
  rule controls {
    'controls' '{'
    [
      [ 'inet' [   [ <ip-addr> | '*' ]
                 | [ 'port' <ip-port> ]
               ] *
        'allow' '{' <address-match-list> '}'
          [
            [ 'keys' '{' <key-list> '}' ]
          |
            [ 'read-only' <yes-or-no> ]
          ] *
        ';'
      ]
    |
      [ 'unix' <path> 'perm' <number> 'owner' <number> 'group' <number>
        [ 'keys' '{' <key-list> '}' ]?
        [ 'read-only' <yes-or-no> ]?
        ';'
      ]
    ] *
    '}' ';'
  }
  regex include {
    'include' <path>
  }
  rule key {
    'key' <domain-name> '{'
      [
        'algorithm' <string> ';'
      |
        'secret' <string> ';'
      ]*
    '}' ';'
  }
  rule logging {
    'logging' '{'
    [
      'channel' <channel-name> '{'
      [
        'file' <path-name>
          [
            'versions' [ <number> | 'unlimited' ]
          |
            'size' <size-spec>
          ]*
      | 'syslog' <syslog-facility>
      | 'stderr'
      | 'null'
      ] + ';'

      [
        'severity' [ 'critical' | 'error' | 'warning' | 'notice' | 'info' | 'debug' <level>? | 'dynamic' ] ';'
      | 'print-category' <yes-or-no> ';'
      | 'print-severity' <yes-or-no> ';'
      | 'print-time' <yes-or-no> ';'
      | 'buffered' <yes-or-no> ';'
      ] *
      '}' ';'
    |
      'category' <category-name> '{'
        [ <channel-name> ';' ] +
      '}' ';'
    ]+
    '}' ';'
  }
  regex lwres {
    'lwres'
  }
  regex masters {
    'masters' <name>
      [ 'port' <ip-port>
      | 'dscp' <ip-dscp>
      ] *
    '{'
      [ <masters-list> ';'
      |  <ip-addr> [ 'port' <ip-port> ';'
                   | 'key' <key> ';'
                   ] *
      ]
    '}' ';'
  }
  rule options {
    'options' '{'
      <option> *
    '}' ';'
  }
  proto regex option { <*> }
  rule option:sym<include>                           { 'include'                           <string> ';' }
  rule option:sym<bogus>                             { 'bogus'                             <yes-or-no> ';' }
  rule option:sym<attach-cache>                      { 'attach-cache'                      <cache-name> ';' }
  rule option:sym<version>                           { 'version'                           <string> ';' }
  rule option:sym<hostname>                          { 'hostname'                          <string> ';' }
  rule option:sym<server-id>                         { 'server-id'                         <string> ';' }
  rule option:sym<directory>                         { 'directory'                         <path-name> ';' }
  rule option:sym<dnstap>                            { 'dnstap'                            '{' [<message-type> ';']+ '}' ';' }
  rule option:sym<dnstap-output>                     { 'dnstap-output'                     [ 'file' | 'unix' ] <path-name> ';' }
  rule option:sym<dnstap-identity>                   { 'dnstap-identity'                   [ <string> | <hostname> | 'none' ] ';' }
  rule option:sym<dnstap-version>                    { 'dnstap-version'                    [ <string> | 'none' ] ';' }
  rule option:sym<fstrm-set-buffer-hint>             { 'fstrm-set-buffer-hint'             <number> ';' }
  rule option:sym<fstrm-set-flush-timeout>           { 'fstrm-set-flush-timeout'           <number> ';' }
  rule option:sym<fstrm-set-input-queue-size>        { 'fstrm-set-input-queue-size'        <number> ';' }
  rule option:sym<fstrm-set-output-notify-threshold> { 'fstrm-set-output-notify-threshold' <number> ';' }
  rule option:sym<fstrm-set-output-queue-model>      { 'fstrm-set-output-queue-model'      [ 'mpsc' | 'spsc' ] ';' }
  rule option:sym<fstrm-set-output-queue-size>       { 'fstrm-set-output-queue-size'       <number> ';' }
  rule option:sym<fstrm-set-reopen-interval>         { 'fstrm-set-reopen-interval'         <number> ';' }
  rule option:sym<geoip-directory>                   { 'geoip-directory'                   <path-name> ';' }
  rule option:sym<key-directory>                     { 'key-directory'                     <path-name> ';' }
  rule option:sym<managed-keys-directory>            { 'managed-keys-directory'            <path-name> ';' }
  rule option:sym<named-xfer>                        { 'named-xfer'                        <path-name> ';' }
  rule option:sym<tkey-gssapi-keytab>                { 'tkey-gssapi-keytab'                <path-name> ';' }
  rule option:sym<tkey-gssapi-credential>            { 'tkey-gssapi-credential'            <domain-name> ';' }
  rule option:sym<tkey-domain>                       { 'tkey-domain'                       <domain-name> ';' }
  rule option:sym<tkey-dhkey>                        { 'tkey-dhkey'                        <key_name> <key_tag> ';' }
  rule option:sym<cache-file>                        { 'cache-file'                        <path-name> ';' }
  rule option:sym<dump-file>                         { 'dump-file'                         <path-name> ';' }
  rule option:sym<bindkeys-file>                     { 'bindkeys-file'                     <path-name> ';' }
  rule option:sym<lock-file>                         { 'lock-file'                         <path-name> ';' }
  rule option:sym<secroots-file>                     { 'secroots-file'                     <path-name> ';' }
  rule option:sym<session-keyfile>                   { 'session-keygile'                   <path-name> ';' }
  rule option:sym<session-keyname>                   { 'session-keyname'                   <key_name> ';' }
  rule option:sym<session-keyalg>                    { 'sesion-keyalg'                     <algorithm-id> ';' }
  rule option:sym<memstatistics>                     { 'memstatistics'                     <yes-or-no> ';' }
  rule option:sym<memstatistics-file>                { 'memstatistics-file'                <path-name> ';' }
  rule option:sym<pid-file>                          { 'pid-file'                          <path-name> ';' }
  rule option:sym<recursing-file>                    { 'recursing-file'                    <path-name> ';' }
  rule option:sym<statistics-file>                   { 'statistics-file'                   <path-name> ';' }
  rule option:sym<zone-statistics>                   { 'zone-statistics'                   [ 'full' | 'terse' | 'none' ] ';' }
  rule option:sym<auth-nxdomain>                     { 'auth-nxdomain'                     <yes-or-no> ';' }
  rule option:sym<nxdomain-redirect>                 { 'nxdomain-redirect'                 <string> ';' }
  rule option:sym<deallocate-on-exit>                { 'deallocate-on-exit'                <yes-or-no> ';' }
#  rule option:sym<dialup dialup_option ; ]
#  rule option:sym<fake-iquery <yes-or-no> ; ]
#  rule option:sym<fetch-glue <yes-or-no> ; ]
#  rule option:sym<flush-zones-on-shutdown <yes-or-no> ; ]
#  rule option:sym<has-old-clients <yes-or-no> ; ]
#  rule option:sym<host-statistics <yes-or-no> ; ]
#  rule option:sym<host-statistics-max number ; ]
#  rule option:sym<minimal-any <yes-or-no> ; ]
#  rule option:sym<minimal-responses ( <yes-or-no> | no-auth | no-auth-recursive ) ; ]
#  rule option:sym<multiple-cnames <yes-or-no> ; ]
  rule option:sym<notify> { 'notify' [ <yes-or-no> | 'explicit' | 'master-only' ] ';' }
#  rule option:sym<recursion <yes-or-no> ; ]
#  rule option:sym<send-cookie <yes-or-no> ; ]
#  rule option:sym<require-server-cookie <yes-or-no> ; ]
#  rule option:sym<cookie-algorithm algorithm_id ; ]
#  rule option:sym<cookie-secret secret_string ; ]
#  rule option:sym<nocookie-udp-size number ; ]
#  rule option:sym<request-nsid <yes-or-no> ; ]
#  rule option:sym<rfc2308-type1 <yes-or-no> ; ]
#  rule option:sym<use-id-pool <yes-or-no> ; ]
#  rule option:sym<maintain-ixfr-base <yes-or-no> ; ]
#  rule option:sym<ixfr-from-differences ( <yes-or-no> | master | slave ) ; ]
#  rule option:sym<auto-dnssec ( allow | maintain | off ) ; ]
#  rule option:sym<dnssec-enable <yes-or-no> ; ]
#  rule option:sym<dnssec-validation ( <yes-or-no> | auto ) ; ]
#  rule option:sym<dnssec-lookaside ( auto | no | domain trust-anchor domain ) ; ]
#  rule option:sym<dnssec-must-be-secure domain <yes-or-no> ; ]
#  rule option:sym<dnssec-accept-expired <yes-or-no> ; ]
#  rule option:sym<forward ( only | first ) ; ]
#  rule option:sym<forwarders { ( ip_addr [ port ip_port ] [ dscp ip_dscp ] ; ) ...  } ; ]
#  rule option:sym<dual-stack-servers [ port ip_port ] [ dscp ip_dscp ] { ( ( domain-name | ip_addr ) [ port ip_port ] [ dscp ip_dscp ] ; ) ...  } ; ]
  rule option:sym<check-names> { 'check-names' [ 'master' | 'slave' | 'response' ] [ 'warn' | 'fail' | 'ignore' ] ';' }
#  rule option:sym<check-dup-records ( warn | fail | ignore ) ; ]
#  rule option:sym<check-mx ( warn | fail | ignore ) ; ]
#  rule option:sym<check-wildcard <yes-or-no> ; ]
#  rule option:sym<check-integrity <yes-or-no> ; ]
#  rule option:sym<check-mx-cname ( warn | fail | ignore ) ; ]
#  rule option:sym<check-srv-cname ( warn | fail | ignore ) ; ]
#  rule option:sym<check-sibling <yes-or-no> ; ]
#  rule option:sym<check-spf ( warn | ignore ) ; ]
#  rule option:sym<allow-new-zones <yes-or-no> ; ]
  rule option:sym<allow-notify> { 'allow-notify' '{' <address-match-list> '}' ';' }
  rule option:sym<allow-query> { 'allow-query' '{' <address-match-list> '}' ';' }
#  rule option:sym<allow-query-on { <address-match-list> } ; ]
  rule option:sym<allow-query-cache> { 'allow-query-cache' '{' <address-match-list> '}' ';' }
#  rule option:sym<allow-query-cache-on { <address-match-list> } ; ]
  rule option:sym<allow-transfer> { 'allow-transfer' '{' <address-match-list> '}' ';' }
  rule option:sym<allow-recursion> { 'allow-recursion' '{' <address-match-list> '}' ';' }
#  rule option:sym<allow-recursion-on { <address-match-list> } ; ]
#  rule option:sym<allow-update { <address-match-list> } ]
#  rule option:sym<allow-update-forwarding { <address-match-list> } ; ]
#  rule option:sym<automatic-interface-scan <yes-or-no> ; ]
#  rule option:sym<geoip-use-ecs <yes-or-no> ; ]
#  rule option:sym<update-check-ksk <yes-or-no> ; ]
#  rule option:sym<dnssec-update-mode ( maintain | no-resign ) ; ]
#  rule option:sym<dnssec-dnskey-kskonly <yes-or-no> ; ]
#  rule option:sym<dnssec-loadkeys-interval number ; ]
#  rule option:sym<dnssec-secure-to-insecure <yes-or-no> ; ]
#  rule option:sym<try-tcp-refresh <yes-or-no> ; ]
#  rule option:sym<allow-v6-synthesis { <address-match-list> } ; ]
#  rule option:sym<blackhole { <address-match-list> } ; ]
#  rule option:sym<keep-response-order { <address-match-list> } ; ]
#  rule option:sym<no-case-compress { <address-match-list> } ; ]
#  rule option:sym<message-compression <yes-or-no> ; ]
#  rule option:sym<use-v4-udp-ports { port_list } ; ]
#  rule option:sym<avoid-v4-udp-ports { port_list } ; ]
#  rule option:sym<use-v6-udp-ports { port_list } ; ]
#  rule option:sym<avoid-v6-udp-ports { port_list } ; ]
#  rule option:sym<listen-on [ port ip_port ] [ dscp ip_dscp ] { <address-match-list> } ; ]
  rule option:sym<listen-on-v6> { 'listen-on-v6' [ [ 'port' <ip-port> ] | [ 'dscp' <ip-dscp> ] ]* '{' <address-match-list> '}' ';' }
#  rule option:sym<query-source ( [ address ] ( ip4_addr | * ) ) [ port ( ip_port | * ) ] [ dscp ip_dscp ] ] 
#  rule option:sym<query-source-v6 ( [ address ] ( ip6_addr | * ) ) [ port ( ip_port | * ) ] [ dscp ip_dscp ] ] ;
#  rule option:sym<use-queryport-pool <yes-or-no> ; ]
#  rule option:sym<queryport-pool-ports number ; ]
#  rule option:sym<queryport-pool-updateinterval number ; ]
#  rule option:sym<max-records number ; ]
#  rule option:sym<max-transfer-time-in number ; ]
#  rule option:sym<max-transfer-time-out number ; ]
#  rule option:sym<max-transfer-idle-in number ; ]
#  rule option:sym<max-transfer-idle-out number ; ]
#  rule option:sym<reserved-sockets number ; ]
  rule option:sym<recursive-clients> { 'recursive-clients' <number> ';' }
#  rule option:sym<tcp-clients number ; ]
#  rule option:sym<clients-per-query number ; ]
#  rule option:sym<max-clients-per-query number ; ]
#  rule option:sym<fetches-per-server number [ ( drop | fail ) ] ; ]
#  rule option:sym<fetches-per-zone number [ ( drop | fail ) ] ; ]
#  rule option:sym<fetch-quota-params number fixedpoint fixedpoint fixedpoint ; ]
#  rule option:sym<notify-rate number ; ]
#  rule option:sym<startup-notify-rate number ; ]
#  rule option:sym<serial-query-rate number ; ]
#  rule option:sym<serial-queries number ; ]
#  rule option:sym<tcp-listen-queue number ; ]
#  rule option:sym<transfer-format ( one-answer | many-answers ) ; ]
#  rule option:sym<transfer-message-size number ; ]
#  rule option:sym<transfers-in number ; ]
#  rule option:sym<transfers-out number ; ]
#  rule option:sym<transfers-per-ns number ; ]
#  rule option:sym<transfer-source ( ip4_addr | * )
#  rule option:sym<port ip_port ] [ dscp ip_dscp ] ; ]
#  rule option:sym<transfer-source-v6 ( ip6_addr | * )
#  rule option:sym<port ip_port ] [ dscp ip_dscp ] ; ]
#  rule option:sym<alt-transfer-source ( ip4_addr | * )
#  rule option:sym<port ip_port ] [ dscp ip_dscp ] ; ]
#  rule option:sym<alt-transfer-source-v6 ( ip6_addr | * )
#  rule option:sym<port ip_port ] [ dscp ip_dscp ] ; ]
#  rule option:sym<use-alt-transfer-source <yes-or-no> ; ]
#  rule option:sym<notify-delay seconds ; ]
#  rule option:sym<notify-source ( ip4_addr | * )
#  rule option:sym<port ip_port ] [ dscp ip_dscp ] ; ]
#  rule option:sym<notify-source-v6 ( ip6_addr | * )
#  rule option:sym<port ip_port ] [ dscp ip_dscp ] ; ]
  rule option:sym<notify-to-soa> { 'notify-to-soa' <yes-or-no> ';' }
#  rule option:sym<also-notify [ port ip_port] [ dscp ip_dscp] { ( masters | ip_addr [ port ip_port ] ) [ key key_name ] ; ...  } ; ]
#  rule option:sym<max-ixfr-log-size number ; ]
#  rule option:sym<max-journal-size size_spec ; ]
#  rule option:sym<coresize size_spec ; ]
#  rule option:sym<datasize size_spec ; ]
#  rule option:sym<files size_spec ; ]
#  rule option:sym<stacksize size_spec ; ]
#  rule option:sym<cleaning-interval number ; ]
#  rule option:sym<heartbeat-interval number ; ]
#  rule option:sym<interface-interval number ; ]
#  rule option:sym<statistics-interval number ; ]
#  rule option:sym<topology { <address-match-list> } ; ]
#  rule option:sym<sortlist { <address-match-list> } ; ]
#  rule option:sym<rrset-order { order_spec ; ... } ; ]
#  rule option:sym<lame-ttl number ; ]
#  rule option:sym<max-ncache-ttl number ; ]
#  rule option:sym<max-cache-ttl number ; ]
#  rule option:sym<max-zone-ttl ( unlimited | number ) ; ]
#  rule option:sym<serial-update-method ( increment | unixtime | date ) ; ]
#  rule option:sym<servfail-ttl number ; ]
#  rule option:sym<sig-validity-interval number [number] ; ]
#  rule option:sym<sig-signing-nodes number ; ]
#  rule option:sym<sig-signing-signatures number ; ]
#  rule option:sym<sig-signing-type number ; ]
#  rule option:sym<min-roots number ; ]
#  rule option:sym<use-ixfr <yes-or-no> ; ]
#  rule option:sym<provide-ixfr <yes-or-no> ; ]
#  rule option:sym<request-ixfr <yes-or-no> ; ]
#  rule option:sym<request-expire <yes-or-no> ; ]
#  rule option:sym<treat-cr-as-space <yes-or-no> ; ]
#  rule option:sym<min-refresh-time number ; ]
#  rule option:sym<max-refresh-time number ; ]
#  rule option:sym<min-retry-time number ; ]
#  rule option:sym<max-retry-time number ; ]
#  rule option:sym<nta-lifetime duration ; ]
#  rule option:sym<nta-recheck duration ; ]
#  rule option:sym<port ip_port ; ]
#  rule option:sym<dscp ip_dscp ; ]
#  rule option:sym<additional-from-auth <yes-or-no> ; ]
#  rule option:sym<additional-from-cache <yes-or-no> ; ]
#  rule option:sym<random-device <path-name> ; ]
#  rule option:sym<max-cache-size size_or_percent ; ]
#  rule option:sym<match-mapped-addresses <yes-or-no> ; ]
#  rule option:sym<filter-aaaa-on-v4 ( <yes-or-no> | break-dnssec ) ; ]
#  rule option:sym<filter-aaaa-on-v6 ( <yes-or-no> | break-dnssec ) ; ]
#  rule option:sym<filter-aaaa { <address-match-list> } ; ]
#  rule option:sym<dns64 ipv6-prefix { [ clients { <address-match-list> } ; ] [ mapped { <address-match-list> } ; ] [ exclude { <address-match-list> } ; ] [ suffix ip6-address ; ] [ recursive-only <yes-or-no> ; ] [ break-dnssec <yes-or-no> ; ] } ; ]
#  rule option:sym<dns64-server name ]
#  rule option:sym<dns64-contact name ]
#  rule option:sym<preferred-glue ( A | AAAA | none ); ]
#  rule option:sym<edns-udp-size number ; ]
#  rule option:sym<max-udp-size number ; ]
#  rule option:sym<max-rsa-exponent-size number ; ]
#  rule option:sym<root-delegation-only [ exclude { namelist } ] ; ]
#  rule option:sym<querylog <yes-or-no> ; ]
#  rule option:sym<disable-algorithms domain { algorithm ; ... } ; ]
#  rule option:sym<disable-ds-digests domain { digest_type ; ... } ; ]
#  rule option:sym<acache-enable <yes-or-no> ; ]
#  rule option:sym<acache-cleaning-interval number ; ]
#  rule option:sym<max-acache-size size_spec ; ]
#  rule option:sym<max-recursion-depth number ; ]
#  rule option:sym<max-recursion-queries number ; ]
  rule option:sym<masterfile-format> { 'masterfile-format' [ 'text' | 'raw' | 'map' ] ';' }
#  rule option:sym<masterfile-style ( relative | full ) ; ]
#  rule option:sym<empty-server name ; ]
#  rule option:sym<empty-contact name ; ]
#  rule option:sym<empty-zones-enable <yes-or-no> ; ]
#  rule option:sym<disable-empty-zone zone_name ; ]
#  rule option:sym<zero-no-soa-ttl <yes-or-no> ; ]
#  rule option:sym<zero-no-soa-ttl-cache <yes-or-no> ; ]
#  rule option:sym<resolver-query-timeout number ; ]
#  rule option:sym<deny-answer-addresses { <address-match-list> } [ except-from { namelist } ] ; ]
#  rule option:sym<deny-answer-aliases { namelist } [ except-from { namelist } ] ; ]
#  rule option:sym<prefetch number [ number ] ; ]
#  rule option:sym<rate-limit { [ responses-per-second number ; ] [ referrals-per-second number ; ] [ nodata-per-second number ; ] [ nxdomains-per-second number ; ] [ errors-per-second number ; ] [ all-per-second number ; ] [ window number ; ] [ log-only <yes-or-no> ; ] [ qps-scale number ; ] [ ipv4-prefix-length number ; ] [ ipv6-prefix-length number ; ] [ slip number ; ] [ exempt-clients { <address-match-list> } ; ] [ max-table-size number ; ] [ min-table-size number ; ] } ; ]
#  rule option:sym<response-policy { zone zone_name [ policy ( given | disabled | passthru | drop | tcp-only | nxdomain | nodata | cname domain ) ] [ recursive-only <yes-or-no> ] [ log <yes-or-no> ] [ max-policy-ttl number ] ; ...  } [ recursive-only <yes-or-no> ] [ max-policy-ttl number ] [ break-dnssec <yes-or-no> ] [ min-ns-dots number ] [ nsip-wait-recurse <yes-or-no> ] [ qname-wait-recurse <yes-or-no> ] ; ]
#  rule option:sym<catalog-zones { zone quoted_string [ default-masters [ port ip_port ] [ dscp ip_dscp ] { ( masters_list | ip_addr [port ip_port] [ key key_name] ) ; ...  } ] [ zone-directory <path-name> ] [ in-memory <yes-or-no> ] [ min-update-interval interval ] ; ...  } ; ]
#  rule option:sym<v6-bias number ; ]


  regex server {
    'server' <ip-addr>  '{'
      <server-option> *
    '}'
  }
  proto regex server-option { <*> }
  regex server-option:syn<bogus> { 'bogus' <yes-or-no> ';' }

  regex statistics-channels {
    'statistics-channels' '{'
      [ 'inet' [ <ip-addr> | '*' ]
               [ 'port' <ip-port> ] ?
               [ 'allow' '{' <address-match-list> '}' ]
      ]
    '}' ';'
  }

  regex trusted-keys {
    'trusted-keys' '{'
      [ <domain-name> <flags> <protocol> <algorithm> <key-data> ';' ] +
    '}' ';'
  }

  regex managed-keys {
    'managed-keys' '{'
      [ <domain-name> <initial-key> <flags> <protocol> <algorithm> <key-data> ';' ] +
    '}' ';'
  }

  regex view {
    'view' '{'
      'match-clients' '{' <address-match-list> '}' ';'
      'match-destination' '{' <address-match-list> '}' ';'
      'match-recursive-only' <yes-or-no> ';'
    [ <view-option> ';' ] *
    [ <zone-statement> ';' ] *
    '}' ';'
  }

  proto regex zone { <*> }
  rule zone:sym<master>          { 'zone' <domain-name> <class>? '{' 'type' 'master'      ';' <zone-option>* '}' ';' }
  rule zone:sym<slave>           { 'zone' <domain-name> <class>? '{' 'type' 'slave'       ';' <zone-option>* '}' ';' }
  rule zone:sym<hint>            { 'zone' <domain-name> <class>? '{' 'type' 'hint'        ';' <zone-option>* '}' ';' }
  rule zone:sym<stub>            { 'zone' <domain-name> <class>? '{' 'type' 'stub'        ';' <zone-option>* '}' ';' }
  rule zone:sym<static-stub>     { 'zone' <domain-name> <class>? '{' 'type' 'static-stub' ';' <zone-option>* '}' ';' }
  rule zone:sym<forward>         { 'zone' <domain-name> <class>? '{' 'type' 'forward'     ';' <zone-option>* '}' ';' }
  rule zone:sym<redirect>        { 'zone' <domain-name> <class>? '{' 'type' 'redirect'    ';' <zone-option>* '}' ';' }
  rule zone:sym<in-view>         { 'zone' <domain-name> <class>? '{' [ 'in-view' <string>   ';' ]? }
  rule zone:sym<delegation-only> { 'zone' <domain-name> <class>? '{' 'type' 'delegation-only' ';' ']' ';' }

  proto regex zone-option { <*> }
  rule zone-option:sym<allow-query>               { 'allow-query'               '{' <address-match-list> '}' ';' }
  rule zone-option:sym<allow-query-on>            { 'allow-query-on'            '{' <address-match-list> '}' ';' }
  rule zone-option:sym<allow-transfer>            { 'allow-transfer'            '{' <address-match-list> '}' ';' }
  rule zone-option:sym<allow-update>              { 'allow-update'              '{' <address-match-list> '}' ';' }
  rule zone-option:sym<allow-notify>              { 'allow-notify'              '{' <address-match-list> '}' ';' }
  rule zone-option:sym<allow-update-forwarding>   { 'allow-update-forwarding'   '{' <address-match-list> '}' ';' }
  rule zone-option:sym<update-check-ksk>          { 'update-check-ksk'          <yes-or-no> ';' }
  rule zone-option:sym<dnssec-dnskey-kskonly>     { 'dnssec-dnskey-kskonly'     <yes-or-no> ';' }
  rule zone-option:sym<dnssec-loadkeys-interval>  { 'dnssec-loadkeys-interval'  <number> ';' }
  rule zone-option:sym<dnssec-secure-to-insecure> { 'dnssec-secure-to-insecure' <yes-or-no> ';' }
  rule zone-option:sym<update-policy>             { 'update-policy'             [ 'local' | '{' [ <update-policy-rule> ';' ]+ ']' ] ';' }
  rule zone-option:sym<also-notify>               { 'also-notify'               [ [ 'port' <ip-port> ] | [ 'dscp' <ip-dscp> ] ]*
                                                                                '{'
                                                                                  [
                                                                                    | <masters-list>
                                                                                    | [ <ip-addr> [ 'port' <ip-port> ]? 
                                                                                      ]
                                                                                      [ 'key' <key-id> ]?
                                                                                      ';' 
                                                                                  ]*
                                                                                  '}' ';'
                                                  }
  rule zone-option:sym<delegation-only>           { 'delegation-only'           <yes-or-no> ';' }
  rule zone-option:sym<check-names>               { 'check-names'               'warn' | 'fail' | 'ignore' ';' }
  rule zone-option:sym<check-mx>                  { 'check-mx'                  'warn' | 'fail' | 'ignore' ';' }
  rule zone-option:sym<check-wildcard>            { 'check-wildcard'            <yes-or-no> ';' }
  rule zone-option:sym<check-spf>                 { 'check-spf'                 'warn' | 'ignore' ';' }
  rule zone-option:sym<check-integrity>           { 'check-integrity'           <yes-or-no> ';' }
  rule zone-option:sym<dialup>                    { 'dialup'                    <dialup-option> ';' }
  rule zone-option:sym<dnssec-update-mode>        { 'dnssec-update-mode'        [ 'maintain' | 'no-resign' ] ';' }
  rule zone-option:sym<file>                      { 'file'                      <string> ';' }
  rule zone-option:sym<masterfile-format>         { 'masterfile-format'         [ 'text' | 'raw' | 'map' ] ';' }
  rule zone-option:sym<journal>                   { 'journal'                   <string> ';' }
  rule zone-option:sym<max-journal-size>          { 'max-journal-size'          <size-spec> ';' }
  rule zone-option:sym<forward>                   { 'forward'                   [ 'only' | 'first' ] ';' }
  rule zone-option:sym<forwarders>                { 'forwarders'                '{'
                                                                                [ <ip-addr>
                                                                                  [ [ 'port' <ip-port> ] | [ 'dscp' <ip-dscp> ] ]*
                                                                                  ';'
                                                                                ]+
                                                                                '}' ';'
                                                  }
  rule zone-option:sym<ixfr-base>                 { 'ixfr-base'                 <string> ';' }
  rule zone-option:sym<ixfr-from-differences>     { 'ixfr-from-differences'     <yes-or-no> ';' }
  rule zone-option:sym<ixfr-tmp-file>             { 'ixfr-tmp-file'             <string> ';' }
  rule zone-option:sym<maintain-ixfr-base>        { 'maintain-ixfr-base'        <yes-or-no> ';' }
  rule zone-option:sym<masters>                   { 'masters'                   [ [ 'port' <ip-port> ] | [ 'dscp' <ip-dscp> ] ]*
                                                                                '{'
                                                                                [ [ <masters-list>
                                                                                  | <ip-addr> [ [ 'port' <ip-port> ] | [ 'dscp' <ip-dscp> ] ]* 
                                                                                              ]
                                                                                ]*
                                                                                '}' ';' }
  rule zone-option:sym<max-ixfr-log-size>         { 'max-ixfr-log-size'         <number> ';' }
  rule zone-option:sym<max-transfer-idle-in>      { 'max-transfer-idle-in'      <number> ';' }
  rule zone-option:sym<max-transfer-idle-out>     { 'max-transfer-idle-out'     <number> ';' }
  rule zone-option:sym<max-transfer-time-in>      { 'max-transfer-time-in'      <number> ';' }
  rule zone-option:sym<max-transfer-time-out>     { 'max-transfer-time-out'     <number> ';' }
  rule zone-option:sym<notify>                    { 'notify'                    [ <yes-or-no>  | 'explicit' | 'master-only' ] ';' }
  rule zone-option:sym<notify-delay>              { 'notify-delay'              <seconds> ';' }
  rule zone-option:sym<notify-to-soa>             { 'notify-to-soa'             <yes-or-no> ';' }
  rule zone-option:sym<pubkey>                    { 'pubkey'                    <number> <number> <number> <string> ';' }
  rule zone-option:sym<transfer-source>           { 'transfer-source'           [ <ip4-addr> | '*' ] 
                                                                                [ [ 'port' <ip-port> ] | [ 'dscp' <ip-dscp> ] ]* ';' }
  rule zone-option:sym<transfer-source-v6>        { 'transfer-source-v6'        [ <ip6-addr> | '*' ] 
                                                                                [ [ 'port' <ip-port> ] | [ 'dscp' <ip-dscp> ] ]* ';' }
  rule zone-option:sym<alt-transfer-source>       { 'alt-transfer-source'       [ <ip4-addr> | '*' ] 
                                                                                [ [ 'port' <ip-port> ] | [ 'dscp' <ip-dscp> ] ]* ';' }
  rule zone-option:sym<alt-transfer-source-v6>    { 'alt-transfer-source-v6'    [ <ip6-addr> | '*' ] 
                                                                                [ [ 'port' <ip-port> ] | [ 'dscp' <ip-dscp> ] ]* ';' }
  rule zone-option:sym<use-alt-transfer-source>   { 'use-alt-transfer-source'   <yes-or-no> ';' }
  rule zone-option:sym<notify-source>             { 'notify-source'             [ <ip4-addr> | '*' ] 
                                                                                [ [ 'port' <ip-port> ] | [ 'dscp' <ip-dscp> ] ]* ';'
                                                  }
  rule zone-option:sym<notify-source-v6>          { 'notify-source-v6'          [ <ip6-addr> | '*' ] 
                                                                                [ [ 'port' <ip-port> ] | [ 'dscp' <ip-dscp> ] ]* ';' }
  rule zone-option:sym<server-addresses>          { 'server-addresses'          '{' [ <ip-addr> ';' ]+ ';' }
  rule zone-option:sym<server-names>              { 'server-names'              '{' <namelist> '}' ';' }
  rule zone-option:sym<zone-statistics>           { 'zone-statistics'           [ 'full' | 'terse' | 'none' ] ';' }
  rule zone-option:sym<sig-validity-interval>     { 'sig-validity-interval'     <number> <number>? ';' }
  rule zone-option:sym<sig-signing-nodes>         { 'sig-signing-nodes'         <number> ';' }
  rule zone-option:sym<sig-signing-signatures>    { 'sig-signing-signatures'    <number> ';' }
  rule zone-option:sym<sig-signing-type>          { 'sig-signing-type'          <number> ';' }
  rule zone-option:sym<database>                  { 'database'                  <string> ';' }
  rule zone-option:sym<min-refresh-time>          { 'min-refresh-time'          <number> ';' }
  rule zone-option:sym<max-refresh-time>          { 'max-refresh-time'          <number> ';' }
  rule zone-option:sym<min-retry-time>            { 'min-retry-time'            <number> ';' }
  rule zone-option:sym<max-retry-time>            { 'max-retry-time'            <number> ';' }
  rule zone-option:sym<key-directory>             { 'key-directory'             <path-name> ';' }
  rule zone-option:sym<auto-dnssec>               { 'auto-dnssec'               [ 'allow' | 'maintain' | 'off' ] ';' }
  rule zone-option:sym<inline-signing>            { 'inline-signing'            <yes-or-no> ';' }
  rule zone-option:sym<multi-master>              { 'multi-master'              <yes-or-no> ';' }
  rule zone-option:sym<zero-no-soa-ttl>           { 'zero-no-soa-ttl'           <yes-or-no> ';' }
  rule zone-option:sym<serial-update-method>      { 'serial-update-method'      [ 'increment' | 'unixtime' | 'date' ] ';' }
  rule zone-option:sym<max-zone-ttl>              { 'max-zone-ttl'              <number> ';' }
  rule zone-option:sym<try-tcp-refresh>           { 'try-tcp-refresh'           <yes-or-no> ';' }

  token number {
    <[ 0..9 ]> +
  }
  token size-spec {
    <number> <[kKmMgG]>?
  }
  token yes-or-no {
      'yes'
    | 'no'
    | 'true'
    | 'false'
    | '0'
    | '1'
  }
  rule address-match-list {
    [ <address-match-list-element> ';'] +
  }
  rule address-match-list-element {
      '!'? <ip-addr> [ '/' <number> ]?
    | '!'? 'key' <bare-domain-name>
    | '!'? <acl-name>
    | '!'? '"' <acl-name> '"'
    | '!'? '{' <address-match-list> '}'
  }

  rule masters-list {
    [ <masters-list-element> ';' ] +
  }

  rule masters-list-element { # TODO: incomplete
      <ip-addr> [ 'key' <key-id> ]?
    | 'key' <key-id>
  }

  token ip4-addr {
    <number> ** 4 % '.' [ '/' <number> ]?
  }
  token ip6-addr {
    <[ 0..9 a..f A..F ]> ** 2..16 % ':'  [ '/' <number> ]?
  }
  rule ip-addr { <ip4-addr> | <ip6-addr> }
  rule key-list {
    [ <key-id> ';' ] +
  }
  regex key-id {
    <bare-domain-name>
  }
  token name {
    <[ a..z A..Z _ \- 0..9 ]>+ 
  }
  token acl-name {
    <name>
  }
  token channel-name {
    <name>
  }
  token category-name {
    <name>
  }
  token syslog-facility {
    <name>
  }

  token bare-domain-name {
    <[ \w . - ]>+
  }

  token domain-name {
    '"' <bare-domain-name> '"'
  }

  token path-name {
    '"' <-[ " \n ]>+ '"'
  }

  token string {
    '"' <-[ " \n ]>+ '"'
  }

  token class { :i
    '"' 'in' '"'
  }
}

#dd Config.subparse('acl fred { 1.2.3.4; };');
#dd Config.subparse('acl fred { 1.2.3.4/45; };');
#dd Config.subparse('acl fred { "domain.name"; };');
#dd Config.subparse('acl fred { ! { 1.2.3.4; "domain.name"; }; };');
#dd Config.subparse('acl fred { "domain.name"; }; acl fred { ! { 1.2.3.4; "domain.name"; }; };');
#dd Config.subparse('options { directory "/var/lib/named"; pid-file "/var/lib/named"; };');
#dd Config.subparse('options { statistics-file "/var/lib/named"; };');
#dd Config.subparse('options { listen-on-v6 { none; }; };');
#dd Config.subparse('options { notify yes; };');
#dd Config.subparse('options { include "None"; };');
#dd Config.subparse('options { allow-recursion { all_dns_servers; 10.112.138.135; 10.61.71.41; 10.63.71.41; };};');
#dd Config.subparse('options { check-names master warn; };');
#dd Config.subparse('options { masterfile-format raw; };');
#dd Config.subparse('options { notify-to-soa     yes; };' );
#dd Config.subparse('zone "eastwestlink.vic.gov.au" { type master; file "master/master/eastwestlink.vic.gov.au"; allow-update { key master.; }; serial-update-method unixtime; allow-transfer { key master.; }; also-notify {203.34.63.241 key ahe.; 203.34.63.244 key ahe.; 10.61.77.8 key ahe.; 10.63.77.25 key ahe.; 203.34.63.241 key dhhs.; 203.34.63.244 key dhhs.; 10.61.77.8 key dhhs.; 10.63.77.25 key dhhs.; 203.34.63.241 key external.; 203.34.63.244 key external.; 203.34.63.241 key internal.; 203.34.63.244 key internal.; 10.61.77.8 key internal.; 10.63.77.25 key internal.;  }; };' );
#dd Config.subparse('zone "environment.vic.gov.au" { type slave; file "slave/internal/environment.vic.gov.au"; masters { 10.61.77.7 key master.; }; };');
#dd Config.subparse('zone "dev.csv.au" { type forward; forward only; forwarders { 10.61.64.100; 10.0.17.100; }; };');
#dd Config.subparse('zone "."                                { type hint;   file "root.hint"; };');
#my $teststring = Q:to/END/;
#acl ext-secondaries {
#        203.10.110.101/32 ;   //ns.netspace.net.au.
#        203.17.103.1/32  ;    //ns2.netspace.net.au.
#        203.94.128.54/32 ; //new ns1.uecomm.net.au.
#        203.14.168.3/32 ;   //ns1.iinet.net.au.
#        203.59.24.3/32 ;   //ns2.iinet.net.au.
#        203.14.169.3/32 ;   //ns3.iinet.net.au.
#
#};
#
#END
my $teststring = 'alfa.conf'.IO.slurp;
#my $teststring = Q:to/END/;
#key "rndckey" {
#        algorithm       "hmac-md5";
#        secret          "rJigjRyZP3DCNiprNZC5ijKmWHukty+Bt9dpZ1sbh38=";
#};
#END
Config.parse($teststring);
#dd ~$/;

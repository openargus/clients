#!/usr/bin/perl
# 
#   Argus-5.0 Client Software.  Tools to read, analyze and manage Argus data.
#   Copyright (c) 2000-2024 QoSient, LLC
#   All Rights Reserved
#  
#  THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
#  AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
#  EXPRESS PERMISSION OF QoSIENT, LLC.
#  
#  QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
#  SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
#  AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
#  SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
#  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
#  IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
#  ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
#  THIS SOFTWARE.
# 
#   raclique.pl - process clique data
#
#

# Complain about undeclared variables
use v5.6.0;
use strict;

$ENV{'PATH'} = '/bin:/usr/bin:/usr/local/bin';

# Used modules
use POSIX;
use DBI;
use JSON;
use qosient::XS::util;
use Time::Local;

use Switch;
use File::Temp qw/ tempfile tempdir /;
use File::Which qw/ which where /;
use CGI qw(:standard);
use Text::CSV_XS;

my $query = new CGI;
my ($val, $stime, $ctime, $lhtime, $ptime, $etime);

# Global variables
my $VERSION = "5.0.3";
my @arglist = ();

my $logfile     = "/tmp/cal.out";

my $tdate       = `date`;
my $remote      = $query->remote_host();
my $soname      = $query->server_name();
my $port        = $query->server_port();

chomp $tdate;

my @selectItems = ();

my @names       = $query->param;
my $dm          = $query->param('dm');
my $tod         = $query->param('td');
my $time        = $query->param('tm');
my $interval    = $query->param('in');
my $filter      = $query->param('fi');
my $option      = $query->param('op');
my $object      = $query->param('ob');
my $database    = $query->param('db');
my $search      = $query->param('se');
my $field       = $query->param('fd');
my $mode        = $query->param('mo');
my $uuid        = $query->param('uu');
my $id          = $query->param('id');
my @tinds       = ();

my $skey        = " ";
my $stype       = "";
my $objs        = "";
my $datename    = "";
my @results     = ();
my $results_ref = \@results;
my @matchAddress;
my $elements    = "";

my @wdays       = qw (sun mon tue wed thu fri sat);
my $clique;

my $f;
my $fname;

($f,  $fname)   = tempfile();

my $debug       = 0;
my $web         = 1;
my $quiet       = 0;
my $force       = 0;
my $done        = 0;
my $qstr        = "";

# Parse the arguements if any

ARG: while (my $arg = shift(@ARGV)) {
    if (!$done) {
      for ($arg) {
         s/^-debug$//    && do { $debug++; next ARG; };
         s/^-quiet$//    && do { $quiet = 1; next ARG; };
         s/^-db$//       && do { $database = shift(@ARGV); next ARG; };
         s/^-dbase$//    && do { $database = shift(@ARGV); next ARG; };
         s/^-dm$//       && do { $dm = shift(@ARGV); next ARG; };
         s/^-t$//        && do { $time = shift(@ARGV); next ARG; };
         s/^-time$//     && do { $time = shift(@ARGV); next ARG; };
         s/^-search$//   && do { $search = shift(@ARGV); next ARG; };
         s/^-se$//       && do { $search = shift(@ARGV); next ARG; };
         s/^-object$//   && do { $object = shift(@ARGV); next ARG; };
         s/^-obj$//      && do { $object = shift(@ARGV); next ARG; };
         s/^-ob$//       && do { $object = shift(@ARGV); next ARG; };
         s/^-field$//    && do { $field = shift(@ARGV); next ARG; };
         s/^-filter$//   && do { $filter = shift(@ARGV); next ARG; };
         s/^-force$//    && do { $force++; next ARG; };
         s/^-uuid$//     && do { $uuid = shift(@ARGV); next ARG; };
         s/^-mode$//     && do { $mode = shift(@ARGV); next ARG; };
         s/^-web$//      && do { $web = 0; next ARG; };
      }
    } else {
      for ($arg) {
         s/\(/\\\(/        && do { ; };
         s/\)/\\\)/        && do { ; };
      }
   }
    $arglist[@arglist + 0] = $arg;
  }

  open (my $fh, '>>', $logfile);

  my $dsn = "DBI:mysql:";
  my $username = "root";
  my $password = '';
  my %attr = ( PrintError=>0, RaiseError=>0 );
  my $dbh = DBI->connect($dsn,$username,$password, \%attr);

  RaCliqueProcessParameters();

  RaCliqueGetClique($fname);

  RaCliqueGenerateOutput($fname);
  RaCliqueCleanUp($fname);
  $dbh->disconnect();
  exit;

sub RaCliqueProcessParameters {
  if (not defined ($object)) {
     $object = "Ndegree";
  }
  if (not defined ($field)) {
     $field = "saddr";
  }
  if (not defined ($mode)) {
     $mode = "local";
  }
  if (not defined ($time)) {
     $time = "-182d";
  }

  if (defined $time) {
      if (index($time,":") != -1) {
         ($time, $tod) = split(/:/, $time);

         if (defined ($tod)) {
            $tod = lc $tod;
            my @days = split(/,/, $tod);
            foreach my $day (@days) {
               my ($tind) = grep { $wdays[$_] eq $day } (0 .. @wdays-1);
               if ($tind >= 0) { push @tinds, $tind; }
            }

            if (scalar @tinds) {
               my $tstr = join ",", @tinds;
               print "DEBUG: RaCliqueProcessParameters: time:'$time' tod:$tstr\n" if $debug;
            }
         }
      }
    ($val, $stime, $etime) = qosient::XS::util::ArgusParseTime($time);
    print "DEBUG: RaCliqueProcessParameters: time:'$time' val:'$val' stime:'$stime' etime:'$etime'\n" if $debug;
  }
  if (not defined ($database)) {
     $database = "hostsInventory";
  }
  if (not defined ($dm)) {
     $dm = "inventory";
  }

# search syntax:  obj=value[,obj=value]
#                 value[,value]

  if (length($search) > 1) {
    my @sobjects;
    my $srchobj;

    $skey = $search;
    
    print "DEBUG: RaCliqueProcessParameters: search:'$search' mode:'$mode'\n" if $debug;

    @sobjects = split(/,/, $search);

    foreach my $sobj (@sobjects) {
      my ($dir, $dobj);

      if (index($sobj,"src:") != -1) {
        $dir = "src";
        $sobj =~ s/src://;
      } elsif (index($sobj,"dst:") != -1) {
        $dir = "dst";
        $sobj =~ s/dst://;
      }

      ($srchobj, $dobj) = split(/=/, $sobj);
      if (not defined $dobj) {
        $dobj = $sobj;
        $srchobj = "";
      } else {
        $sobj = $dobj;
      }

      if (index($sobj, "+") != -1) {
        my @orobj = split('\+', $sobj);
        $dobj = @orobj[0];
      }

      print "DEBUG: RaCliqueProcessParameters: search sobj:'$sobj' dobj:$dobj srchobj:$srchobj\n" if $debug;
   #
   #  search syntax is:
   #    dobj:$dobj  
   #     service = name | uuid | policy | ether | etype | ipv4 | cidr | ipv6 | co | proto | srv | senuuid | senid;
   #     object  = "[field=]objectStr";
   #     search = dataBase:[srchobj:][service:=]object[,[srchobj:][service:=]object];
   #
      my $etherRegex   = '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$';
      my $uuidRegex    = '[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89aAbB][a-f0-9]{3}-[a-f0-9]{12}';
      my $fqdnRegex    = '(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+([a-zA-Z]{2,63}(\.)?)?$)';
      my $ipv4Regex    = '((?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]))';
      my $ipv4CidrRegex  = '(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\/(\d{1}|[0-2]{1}\d{1}|3[0-2])';

      my $ipv6Regex    = '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))';


      if (length($dobj) == 2) {
        my $coRegex   = '^(AF|AX|AL|DZ|AS|AD|AO|AI|AQ|AG|AR|AM|AW|AU|AT|AZ|BS|BH|BD|BB|BY|BE|BZ|BJ|BM|BT|BO|BQ|BA|BW|BV|BR|IO|BN|BG|BF|BI|KH|CM|CA|CV|KY|CF|TD|CL|CN|CX|CC|CO|KM|CG|CD|CK|CR|CI|HR|CU|CW|CY|CZ|DK|DJ|DM|DO|EC|EG|SV|GQ|ER|EE|ET|FK|FO|FJ|FI|FR|GF|PF|TF|GA|GM|GE|DE|GH|GI|GR|GL|GD|GP|GU|GT|GG|GN|GW|GY|HT|HM|VA|HN|HK|HU|IS|IN|ID|IR|IQ|IE|IM|IL|IT|JM|JP|JE|JO|KZ|KE|KI|KP|KR|KW|KG|LA|LV|LB|LS|LR|LY|LI|LT|LU|MO|MK|MG|MW|MY|MV|ML|MT|MH|MQ|MR|MU|YT|MX|FM|MD|MC|MN|ME|MS|MA|MZ|MM|NA|NR|NP|NL|NC|NZ|NI|NE|NG|NU|NF|MP|NO|OM|PK|PW|PS|PA|PG|PY|PE|PH|PN|PL|PT|PR|QA|RE|RO|RU|RW|BL|SH|KN|LC|MF|PM|VC|WS|SM|ST|SA|SN|RS|SC|SL|SG|SX|SK|SI|SB|SO|ZA|GS|SS|ES|LK|SD|SR|SJ|SZ|SE|CH|SY|TW|TJ|TZ|TH|TL|TG|TK|TO|TT|TN|TR|TM|TC|TV|UG|UA|AE|GB|US|UM|UY|UZ|VU|VE|VN|VG|VI|WF|EH|YE|ZM|ZW|ZZ)$';
        if ($dobj =~ /$coRegex/) {
          $stype = "co";
        }
      } elsif (index($dobj,"ether:") != -1) {
        $stype = "ether";
        $sobj =~ s/ether://;
        if ($srchobj eq "") {
               $srchobj = "smac";
        }
      } elsif (index($dobj,"etype:") != -1) {
        $stype = "etype";
        $sobj =~ s/etype://;
        if ($srchobj eq "") {
          $srchobj = "etype";
        }
      } elsif (index($dobj,"policy:") != -1) {
        $stype = "policy";
        $sobj =~ s/policy://;
      } elsif (index($dobj,"fqdn:") != -1) {
        $stype = "fqdn";
        $sobj =~ s/fqdn://;
      } elsif (index($dobj,"dns:") != -1) {
        $stype = "fqdn";
        $sobj =~ s/dns://;
      } elsif (index($dobj,"tld:") != -1) {
        $stype = "tld";
        $sobj =~ s/tld://;
      } elsif (index($dobj,"nld:") != -1) {
        $stype = "nld";
        $sobj =~ s/nld://;
      } elsif (index($dobj,"senid:") != -1) {
        $stype = "senid";
        $sobj =~ s/senid://;
      } elsif (index($dobj,"senuuid:") != -1) {
        $stype = "senuuid";
        $sobj =~ s/senuuid://;
      } elsif ($dobj =~ /$ipv4CidrRegex/) {
        $stype = "cidr";
        if ($srchobj eq "") {
               $srchobj = "saddr";
        }
      } elsif ($dobj =~ /$ipv4Regex/) {
        $stype = "ipv4";
        if ($srchobj eq "") {
               $srchobj = "saddr";
        }
      } elsif ($dobj =~ /$ipv6Regex/) {
        $stype = "ipv6";
        if ($dobj =~ /\d{1}|[0-5]{1}\d{1}|6[0-4]/) {
               $stype = "ipv6Cidr";
        }
        if ($srchobj eq "") {
               $srchobj = "saddr";
        }
      } elsif ($dobj =~ /$fqdnRegex/) {
        $stype = "fqdn";
        if ($srchobj eq "") {
           $srchobj = "name";
        }
      } elsif ($dobj =~ /$etherRegex/) {
        $stype = "ether";
        if ($srchobj eq "") {
               $srchobj = "smac";
        }
      } elsif ($dobj =~ /$uuidRegex/) {
        $stype = "uuid";
      }

      switch ($stype) {
        case "etype" { $database = "ether"; }
        case "ipv4" { }
        case "cidr" { }
        case "tld"  { $database = "dnsAddrs"; }
        case "nld"  { $database = "dnsAddrs"; }
        case "fqdn" { $database = "dnsAddrs"; }
        case "senid" {
           $database = "Sen_Notifications";
           $object = "Senid";
        }
        case "senuuid" {
           $database = "Sen_Notifications";
           $object = "Senuuid";
        }
        case "policy" {
           my @pobj = split(':', $sobj);
           if ($#pobj > 0) {
              push @selectItems, [$stype, @pobj[0], $database];
              if (substr( $pobj[1], 0, 1 ) == 'v') {
                 $stype = "version";
                 $sobj = substr( $pobj[1], 1);
              }
           }
        }
      }
      print "DEBUG: RaCliqueProcessParameters: search terms stype:'$stype' srchobj:'$srchobj' object:'$object' sobj:'$sobj' dbase:'$database'\n" if $debug;
      push @selectItems, [$stype, $srchobj, $sobj, $database];
    }
  }

  switch ($object) {
     case "Hosts" {
       if (not defined ($database)) {
          $database = "inventory";
          $dm = "inventory";
       }
     }
     case "Pkts" {
       if (not defined ($database)) {
          $database = "inventory";
          $dm = "inventory";
       }
     }
     case "Bytes" {
       if (not defined ($database)) {
          $database = "inventory";
          $dm = "inventory";
       }
     }
     case "Pairs" {
       if ((scalar @selectItems) == 0) {
          $database = "ipMatrix";
          $dm = "inventory";
       }
     }
     case "Pcr" {
        $database = "inventory";
        $dm = "inventory";
     }
     case /^Ndegree/ {
       if (index($object, '.') >= 0) {
          ($objs, $mode) = split(/\./, $object);
          $mode = lc $mode;
       }
       if (not defined ($database)) {
          $database = "hostsInventory";
       }
       switch ($database) {
         case "ipMatrix"       { $dm = "inventory"; }
         case "etherMatrix"    { $dm = "inventory"; }
         case "ntpMatrix"      { $dm = "inventory"; }
         case "arpMatrix"      { $dm = "inventory"; }
         case "dnsMatrix"      { $dm = "inventory"; }

         case "ether"          { $dm = "ether"; }
         case "inventory"      { $database = "hostsInventory"; $dm = "inventory"; }
         case "hostsInventory" { $dm = "hostsInventory"; }
       }
     }
     case ["Names","Domains","TLDs"] {
       $dm = "inventory";
     }
     case "Ethers" {
       if (not defined ($database)) {
          $database = "ether";
       }
       $dm = "ether";
     }
     case "Etype" {
       $database = "ether";
       $dm = "etype";
     }
     case "Policy" {
       $database = "policy";
       $dm = "policy";
       $object = "aup";
     }
     case "Ports" {
       $database = "portsInventory";
     }
     case "Clients" {
     }
     case "Servers" {
       $dm = "inventory";
     }
     case ["Esoc", "esoc"] {
       $database = "Sen_Notifications";
       $dm = "esoc";
       $object = "esoc";
     }
     case "Scanners" {
       if (not defined ($database)) {
          $database = "scanners";
          $dm = "inventory";
       }
     }
  }
  print "DEBUG: RaCliqueProcessParameters: $tdate remote $remote soname $soname port $port time $time db $database dm $dm\n" if $debug;
}

sub RaGenerateCliqueSelectionStatement
{
   my $database = shift;
   my $object = shift;
   my $sterm;

   switch ($database) {
      case "inventory" {
         $sterm = "SELECT object,search,ctime,clique From Cliques WHERE object='$object' and search='$skey'";
      }
      case "scanners" {
         $sterm = "SELECT object,search,ctime,clique From Cliques WHERE object='$object' and search='$skey'";
      }
      case /Flows/  {
         $sterm = "SELECT object,search,ctime,clique From Cliques WHERE object='$object' and search='$skey'";
      }
      case /Matrix/  {
         $sterm = "SELECT object,search,ctime,clique From Cliques WHERE object='$object' and search='$skey'";
      }
      case "dnsAddrs" {
         $sterm = "SELECT object,search,ctime,clique From Cliques WHERE object='$object' and search='$skey'";
      }
      case "dnsNames" {
         $sterm = "SELECT object,search,ctime,clique From Cliques WHERE object='$object' and search='$skey'";
      }
      case "Sen_Notifications" {
         $sterm = "SELECT object,search,ctime,clique From Cliques WHERE object='$object' and search='$skey'";
      }
      case "status" {
         $sterm = "SELECT object,search,ctime,clique From Cliques WHERE object='$object' and search='$skey'";
      }
      case "ether" {
         $sterm = "SELECT object,search,ctime,clique From Cliques WHERE object='$object' and search='$skey'";
      }
      case /policy/ {
         $sterm = "SELECT object,search,ctime,clique From Cliques WHERE object='$object' and search='$skey'";
      }
      case /hostsInventory/ {
         $sterm = "SELECT object,search,ctime,clique From Cliques WHERE object='$object' and search='$skey'";
      }
      case /portsInventory/ {
         $sterm = "SELECT object,search,ctime,clique From Cliques WHERE object='$object' and search='$skey'";
      }
   }

   return $sterm;
}

sub RaCliqueGetClique {
   my $file = shift;
   my $dbase = $database;
   my $clique;
   my $ctime;
   my $SQL;

   my $sterms = RaGenerateCliqueSelectionStatement($database, $object);
   
   if (defined $dbh) {
      $dbh->do("use $database;");

      $SQL  = "CREATE TABLE IF NOT EXISTS `Cliques` (";
      $SQL .= "`object` varchar(128),";
      $SQL .= "`search` varchar(128),";
      $SQL .= "`ctime` double(18,6), ";
      $SQL .= "`clique` TEXT, ";
      $SQL .= "PRIMARY KEY (object,search))";

      print "DEBUG: RaCliqueGetClique: creating clique table sql:'$SQL'\n" if $debug;

      if ($dbh->do($SQL)) {
         if ($force == 0) {
            my $sth = $dbh->prepare($sterms);

            print "DEBUG: RaCliqueGetClique: fetching cached clique data dbase:$database sql:'$sterms'\n" if $debug;
            $sth->execute();

            if (my @row = $sth->fetchrow_array()) {
               my $obj = $row[0];
               my $tskey = $row[1];
               $ctime = $row[2];
               $clique = $row[3];

               if (defined $clique) {
                  print $fh "RaCliqueGetClique: clique found ... database:$database object:$obj skey:$tskey ctime:$ctime\n";
                  print "DEBUG: RaCliqueGetClique: clique found ... database:$database object:$obj skey:$tskey ctime:$ctime\n" if $debug;
               }
            }
            $sth->finish();
         }

         switch ($dbase) {
            case "inventory" {
            }
            case "scanners" {
            }
            case /Flows/  {
            }
            case /Matrix/  {
            }
            case "dnsAddrs" {
            }
            case "dnsNames" {
            }
            case "Sen_Notifications" {
            }
            case "status" {
            }
            case "ether" {
            }
            case /policy/ {
            }
            case /hostsInventory/ {
            }
            case /portsInventory/ {
            }
         }
      }
   }

   RaCliqueFetchData($file, $ctime, $clique);
   $database = $dbase;
}

sub RaReturnObject {
   my ($type, $srchobj, $obj, $dbase, $score) = @_;
   my $col;

   switch ($type) {
      case "Clients" { $col = "saddr" }
      case /^Ndegree/ { 
         switch ($dbase) {
            case "hostsInventory" { $col = "count"; return }
         }
         $col = "count";
      }
      case "Names"   { $col = "name" }
      case "co"      { $col = "sco" }
      case "etype"   { $col = "etype" }
      case "ether"   { $col = "smac"; }
      case "fqdn"    { $col = "name"; }
      case "tld"     { $col = "tld"; }
      case "nld"     { $col = "nld"; }
      case "policy"  { $col = "policy" }
      case "version" { $col = "version" }

      case "ipv6Cidr" {
         my ($addr, $mask) = split(/\//, $obj);
         if ($mask == 8) {
            if ($addr =~ /^::/) {
               $addr = "00"
            } else {
               $addr = substr $addr, 0, 2;
            }
         }
         $obj = $addr."%";
         $col = "saddr";
      }

      case "cidr" {
         $col = "saddr";
      }
   }
   if ($srchobj) {
      $col = $srchobj;
   }

   print "DEBUG: RaReturnObject: type:$type srchobj:$srchobj col:$col obj:$obj score:$score\n" if $debug;

   return ($col, $obj);
}


# RaGenerateSearchTerms is called to return the "filter" that will be used. However, for some strategies
# such as for the Sen_Notifications database, we actually will need to do multiple calls to the database
# to get the complete answer.
#
# As a result RaGenerateSearchTerms will return an array of search terms.  The user need to pop them off
# and figure out what to do with them.  As a result we'll return ['dbase', 'sterms'];
#

sub RaGenerateSearchTerms {
   my $file = shift;

   my @sterms = ();
   my $sterm;
   my $dbase;
   my $col;

   print "DEBUG: RaGenerateSearchTerms: start dbase:'$database' obj:'$object' mode:'$mode' file:$file\n" if $debug;

   switch ($database) {
      case "inventory" {
         if ($filter && (length($filter) > 0)) {
            switch ($filter) {
               case "ipv4" {
                  $sterm = "WHERE saddr LIKE \"%.%\"";
               }
               case "ipv6" {
                  $sterm = "WHERE saddr LIKE \"%:%\"";
               }
            }
         }

         if ((scalar @selectItems) > 0) {
            foreach my $sobj (@selectItems) {
               my ($type, $srchobj, $obj, $dbase) = @$sobj;

               if (length($type) > 0) {
                  print "DEBUG: RaGenerateSearchTerms: selects type $type srchobj $srchobj obj $obj\n" if $debug;

                  if (length($sterm) == 0) {
                     $sterm = $sterm . "WHERE ";
                  } else {
                     $sterm = $sterm . " and ";
                  }

                  if (index($obj, "+") != -1) {
                     my ($col, $tobj) = RaReturnObject($type,$srchobj,$obj, $dbase);
                     print "DEBUG: RaGenerateSearchTerms: search type $type obj $obj col $col tobj $tobj\n" if $debug;

                     my @orobj = split('\+', $obj);
                     my $cnt = 0;

                     if ($tobj =~ m/\%/ ) {
                        $sterm = $sterm . "( ";
                        foreach my $oobj (@orobj) {
                           my ($tcol, $tobj) = RaReturnObject($type,$srchobj,$oobj, $dbase);

                           if ($cnt > 0) { $sterm = $sterm . " or "; }
                           $sterm = $sterm . "$tcol LIKE '$tobj'";
                           $cnt++;
                        }
                        $sterm = $sterm . ")";
                     } else {
                        $sterm = $sterm . "$col IN (";
                        foreach my $oobj (@orobj) {
                           my ($tcol, $tobj) = RaReturnObject($type,$srchobj,$oobj, $dbase);

                           if ($cnt > 0) { $sterm = $sterm . ","; }
                           $sterm = $sterm . "'$tobj'";
                           $cnt++;
                        }
                        $sterm = $sterm . ")";
                     }
                  } else {
                     my ($tcol, $tobj) = RaReturnObject($type,$srchobj,$obj, $dbase);
                     if ( $tobj =~ m/\%/ ) {
                        $sterm = $sterm . "$tcol LIKE '$tobj'";
                     } else {
                        if ($type eq "cidr") {
                           $sterm = $sterm . "rasql_compareCidrtoAddr('$tobj', $tcol)";
                        } else {
                           $sterm = $sterm . "$tcol = '$tobj'";
                        }
                     }
                  }
                  if (length($srchobj) > 0) {
                     if ($srchobj eq "src") {
                        $sterm = $sterm . " AND spkts > 0";
                     }
                     if ($srchobj eq "dst") {
                        $sterm = $sterm . " AND dpkts > 0";
                     }
                  }
               }
            }
         } else {
            switch ($object) {
               case "Countries" {
                  $sterm = "WHERE sco!=\"\"";
                  print "DEBUG: RaGenerateSearchTerms: sterms '$sterm'\n" if $debug;
               }
            }
         }
         push @sterms, [$database, $dm, $object, $sterm, $stime];
      }

      case "scanners" {
         if ((scalar @selectItems) > 0) {
            foreach my $sobj (@selectItems) {
               my ($type, $srchobj, $obj, $dbase) = @$sobj;

               if (length($type) > 0) {
                  print "DEBUG: RaGenerateSearchTerms: selects type $type obj $obj\n" if $debug;

                  if (length($sterm) == 0) {
                     $sterm = $sterm . "WHERE ";
                  } else {
                     $sterm = $sterm . " and ";
                  }

                  if (index($obj, "+") != -1) {
                     my ($col, $tobj) = RaReturnObject($type,$srchobj,$obj, $dbase);
                     print "DEBUG: RaGenerateSearchTerms: search type $type obj $obj col $col tobj $tobj\n" if $debug;

                     my @orobj = split('\+', $obj);
                     my $cnt = 0;

                     if ($tobj =~ m/\%/ ) {
                        $sterm = $sterm . "( ";
                        foreach my $oobj (@orobj) {
                           my ($tcol, $tobj) = RaReturnObject($type,$srchobj,$oobj, $dbase);

                           if ($cnt > 0) { $sterm = $sterm . " or "; }
                           $sterm = $sterm . "$tcol LIKE '$tobj'";
                           $cnt++;
                        }
                        $sterm = $sterm . ")";
                     } else {
                        $sterm = $sterm . "$col IN (";
                        foreach my $oobj (@orobj) {
                           my ($tcol, $tobj) = RaReturnObject($type,$srchobj,$oobj, $dbase);

                           if ($cnt > 0) { $sterm = $sterm . ","; }
                           $sterm = $sterm . "'$tobj'";
                           $cnt++;
                        }
                        $sterm = $sterm . ")";
                     }
                  } else {
                     my ($tcol, $tobj) = RaReturnObject($type,$srchobj,$obj, $dbase);
                     if ( $tobj =~ m/\%/ ) {
                        $sterm = $sterm . "$tcol LIKE '$tobj'";
                     } else {
                        $sterm = $sterm . "$tcol = '$tobj'";
                     }
                  }
               }
            }
         }
         push @sterms, [$database, $dm, $object, $sterm, $stime];
      }

      case /Matrix/  {
         if ($filter && (length($filter) > 0)) {
            switch ($filter) {
               case "ipv4" {
                  $sterm = "WHERE saddr LIKE \"%.%\"";
               }
               case "ipv6" {
                  $sterm = "WHERE saddr LIKE \"%:%\"";
               }
            }
         }

         if ((scalar @selectItems) > 0) {
            foreach my $sobj (@selectItems) {
               my ($type, $srchobj, $obj, $dbase) = @$sobj;
               if (length($type) > 0) {
                  my ($tcol, $tobj) = RaReturnObject($type,$srchobj,$obj, $dbase);
                  print "DEBUG: RaGenerateSearchTerms: selects type $type obj $obj tcol $tcol tobj $tobj\n" if $debug;
                  if (length($sterm) == 0) {
                     $sterm = $sterm . "WHERE ";
                  } else {
                     $sterm = $sterm . " and ";
                  }

                  if ( $obj =~ m/\%/ ) {
                     $sterm = $sterm . "saddr LIKE '$obj' or daddr LIKE '$obj'";
                  } else {
                     if (length($srchobj) != 0) {
                        $sterm = $sterm . "$srchobj='$obj'";
                     } else {
                        print "DEBUG: RaGenerateSearchTerms: dbase:'$database' tobj $tobj\n" if $debug;
                        switch($database) {
                           case "etherMatrix" { $sterm = $sterm . "smac='$obj' or dmac='$obj'"; } 
                           case "ipMatrix"    { 
                              switch ($tobj) {
                                 case "sco"   { $sterm = $sterm . "sco='$obj' or dco='$obj'"; }
                                 else         { $sterm = $sterm . "saddr='$obj' or daddr='$obj'"; }
                              }
                           } 
                           case "ipv6Matrix"  { $sterm = $sterm . "saddr='$obj' or daddr='$obj'"; } 
                           case "ntpMatrix"   { $sterm = $sterm . "saddr='$obj' or daddr='$obj'"; } 
                        } 
                        
                     }
                  } 
               }
            }
         }
         push @sterms, [$database, $dm, $object, $sterm, $stime];
      }

      case "ports" {
         if ((scalar @selectItems) > 0) {
            foreach my $sobj (@selectItems) {
               my ($type, $srchobj, $obj, $dbase) = @$sobj;
               if (length($type) > 0) {
                  print "DEBUG: RaGenerateSearchTerms: selects type $type obj $obj\n" if $debug;
                  if (length($sterm) == 0) {
                     $sterm = $sterm . "WHERE ";
                  } else {
                     $sterm = $sterm . " and ";
                  }
                  if ( $obj =~ m/\%/ ) {
                     $sterm = $sterm . "addr LIKE '$obj'";
                  } else {
                     $sterm = $sterm . "addr='$obj'";
                  }
               }
            }
         }
         push @sterms, [$database, $dm, $object, $sterm, $stime];
      }

      case "dnsAddrs" {
         my $found = 0;
         if ((scalar @selectItems) > 0) {
            foreach my $sobj (@selectItems) {
               my ($type, $srchobj, $obj, $dbase) = @$sobj;

               if (length($type) > 0) {
                  print "DEBUG: RaGenerateSearchTerms: selects type $type obj $obj\n" if $debug;

                  if (length($sterm) == 0) {
                     $sterm = $sterm . "WHERE ";
                  } else {
                     $sterm = $sterm . " and ";
                  }

                  if (index($obj, "+") != -1) {
                     my ($col, $tobj) = RaReturnObject($type,$srchobj,$obj, $dbase);
                     print "DEBUG: RaGenerateSearchTerms: search type $type obj $obj col $col tobj $tobj\n" if $debug;

                     my @orobj = split('\+', $obj);
                     my $cnt = 0;

                     if ($tobj =~ m/\%/ ) {
                        $sterm = $sterm . "( ";
                        foreach my $oobj (@orobj) {
                           my ($tcol, $tobj) = RaReturnObject($type,$srchobj,$oobj, $dbase);

                           if ($cnt > 0) { $sterm = $sterm . " or "; }
                           $sterm = $sterm . "$tcol LIKE '$tobj'";
                           $cnt++;
                        }
                        $sterm = $sterm . ")";
                     } else {
                        $sterm = $sterm . "$col IN (";
                        foreach my $oobj (@orobj) {
                           my ($tcol, $tobj) = RaReturnObject($type,$srchobj,$oobj, $dbase);

                           if ($cnt > 0) { $sterm = $sterm . ","; }
                           $sterm = $sterm . "'$tobj'";
                           $cnt++;
                        }
                        $sterm = $sterm . ")";
                     }
                  } else {
                     my ($tcol, $tobj) = RaReturnObject($type,$srchobj,$obj, $dbase);
                     if ( $tobj =~ m/\%/ ) {
                        $sterm = $sterm . "$tcol LIKE '$tobj'";
                     } else {
                        $sterm = $sterm . "$tcol = '$tobj'";
                     }
                  }
               }
            }

         } else {
            switch ($object) {
               case ["Hosts", "Pcr", "Pkts", "Bytes", "Trans"] {
                  $database = "inventory";
                  $dm = "inventory";
               }
               case ["Ether", "Etype"] {
                  $database = "ether";
                  $dm = "inventory";
               }
            }
         }
         push @sterms, [$database, $dm, $object, $sterm, $stime];
      }

      case "dnsNames" {
         if ((scalar @selectItems) > 0) {
            foreach my $sobj (@selectItems) {
               my ($type, $srchobj, $obj, $dbase) = @$sobj;
               if (length($type) > 0) {
      
                  print "DEBUG: RaGenerateSearchTerms: selects type $type obj $obj\n" if $debug;

                  if (length($sterm) == 0) {
                     $sterm = $sterm . "WHERE ";
                  } else {
                     $sterm = $sterm . " and ";
                  }
                  switch ($type) {
                     case "fqdn" { $col = "names" }
                     case "ipv4" { $col = "addr" }
                     case "cidr" {
                        my ($addr, $mask) = split(/\//, $obj);
                        my ($x, $y, $z, $w) = split(/\./, $addr);
                        if ($mask == 24) {
                           $obj = $x . "." . $y . "." . $z . ".%";
                        } elsif ($mask == 16) {
                           $obj = $x . "." . $y . ".%";
                        } elsif ($mask == 8) {
                           $obj = $x . ".%";
                        }
                        $col = "addr";

                     } else {
                        $col = "addr"
                     }
                  }
                  if ( $obj =~ m/\%/ ) {
                     $sterm = $sterm . "$col LIKE '$obj'";
                  } else {
                     $sterm = $sterm . "$col = '$obj'";
                  }
               }
            }

         } else {
            switch ($object) {
               case ["Hosts", "Pcr", "Pkts", "Bytes", "Trans"] {
                  $database = "inventory";
                  $dm = "inventory";
               }
               case ["Ether", "Etype"] {
                  $database = "ether";
                  $dm = "inventory";
               }
            }
         }
         print "DEBUG: RaGenerateSearchTerms: dbase:$database dm:$dm object:$object sterm:$sterm stime:$stime\n" if $debug;
         push @sterms, [$database, $dm, $object, $sterm, $stime];
      }

      case "Sen_Notifications" {
         print "DEBUG: RaGenerateSearchTerms: database:$database object:$object\n" if $debug;
         switch ($object) {
            case [ "Esoc", "esoc" ] {
               push @sterms, [$database, $dm, $object, $sterm, $stime];

            } else {
               if ((scalar @selectItems) > 0) {
                  foreach my $sobj (@selectItems) {
                     my ($type, $srchobj, $obj, $dbase) = @$sobj;
                     if (length($type) > 0) {
                        print "DEBUG: RaGenerateSearchTerms: selects type $type obj $obj\n" if $debug;
                        if (length($sterm) == 0) {
                           $sterm = $sterm . "WHERE ";
                        } else {
                           $sterm = $sterm . " and ";
                        }
                        switch ($type) {
                           case "senuuid" { $col = "uuid" }
                           case "senid"   { $col = "id" }
                        }
                        $sterm = $sterm . "$col='$obj'";
                     }
                  }
               }

               RaFetchSenNotificationData($database, $object, \@sterms, $sterm);
            }
         }
      }

      case "status" {
         my $dtime = time();
         my $stime = RaCliqueGetStartTime($dtime);
         $sterm = "WHERE stime >= $stime AND stime <= $dtime";
         push @sterms, [$database, $dm, $object, $sterm, $stime];
      }

      case "ether" {
         if ((scalar @selectItems) > 0) {
            foreach my $sobj (@selectItems) {
               my ($type, $srchobj, $obj, $dbase) = @$sobj;

               print "DEBUG: RaGenerateSearchTerms: selects type $type srchobj $srchobj obj $obj dbase $dbase\n" if $debug;

               if (length($type) > 0) {
                  if (length($sterm) == 0) {
                     $sterm = $sterm . "WHERE ";
                  } else {
                     $sterm = $sterm . " and ";
                  }

                  if (index($obj, "+") != -1) {
                     my ($col, $tobj) = RaReturnObject($type,$srchobj,$obj,$dbase);
                     print "DEBUG: RaGenerateSearchTerms: search type $type obj $obj col $col tobj $tobj\n" if $debug;

                     my @orobj = split('\+', $obj);
                     my $cnt = 0;

                     if ($tobj =~ m/\%/ ) {
                        $sterm = $sterm . "( ";
                        foreach my $oobj (@orobj) {
                           my ($tcol, $tobj) = RaReturnObject($type,$srchobj,$oobj,$dbase);

                           if ($cnt > 0) { $sterm = $sterm . " or "; }
                           $sterm = $sterm . "$tcol LIKE '$tobj'";
                           $cnt++;
                        }
                        $sterm = $sterm . ")";
                     } else {
                        $sterm = $sterm . "$col IN (";
                        foreach my $oobj (@orobj) {
                           my ($tcol, $tobj) = RaReturnObject($type,$srchobj,$oobj,$dbase);

                           if ($cnt > 0) { $sterm = $sterm . ","; }
                           $sterm = $sterm . "'$tobj'";
                           $cnt++;
                        }
                        $sterm = $sterm . ")";
                     }
                  } else {
                     my ($tcol, $tobj) = RaReturnObject($type,$srchobj,$obj,$dbase);
                     if ( $tobj =~ m/\%/ ) {
                        $sterm = $sterm . "$tcol LIKE '$tobj'";
                     } else {
                        $sterm = $sterm . "$tcol = '$tobj'";
                     }
                  }
               }
            }
         }
         push @sterms, [$database, $dm, $object, $sterm, $stime];
      }

      case /policy/ {
         my $dtime = time();
         my $stime = RaCliqueGetStartTime($dtime);
         $sterm = "WHERE stime >= $stime AND stime <= $dtime";

         if ((scalar @selectItems) > 0) {
            foreach my $sobj (@selectItems) {
               my ($type, $srchobj, $obj, $dbase) = @$sobj;

               if (length($type) > 0) {
                  print "DEBUG: RaGenerateSearchTerms: selects type $type obj $obj\n" if $debug;

                  if (length($sterm) == 0) {
                     $sterm = $sterm . "WHERE ";
                  } else {
                     $sterm = $sterm . " and ";
                  }
                  my ($tcol, $tobj) = RaReturnObject($type,$srchobj,$obj,$dbase);
                  if ( $tobj =~ m/\%/ ) {
                     $sterm = $sterm . "$tcol LIKE '$tobj'";
                  } else {
                     $sterm = $sterm . "$tcol = '$tobj'";
                  }
               }
            }
         }
         push @sterms, [$database, $dm, $object, $sterm, $stime];
      }

      case /hostsInventory/ {
         $sterm = "";

         if ((scalar @selectItems) > 0) {
            foreach my $sobj (@selectItems) {
               my ($type, $srchobj, $obj, $dbase) = @$sobj;

               if (length($type) > 0) {
                  print "DEBUG: RaGenerateSearchTerms: selects type $type obj $obj\n" if $debug;

                  if (length($sterm) == 0) {
                     $sterm .= "WHERE ";
                  } else {
                     $sterm .= " and ";
                  }
                  my ($tcol, $tobj) = RaReturnObject($type,$srchobj,$obj,$dbase);
                  if ( $tobj =~ m/\%/ ) {
                     $sterm .= "$tcol LIKE '$tobj'";
                  } else {
                     $sterm .= "$tcol = '$tobj'";
                  }
               }
            }
         }
         push @sterms, [$database, $dm, $object, $sterm, $stime];
      }

      case /portsInventory/ {
         $sterm = "";

         if ((scalar @selectItems) > 0) {
            foreach my $sobj (@selectItems) {
               my ($type, $srchobj, $obj, $dbase) = @$sobj;

               if (length($type) > 0) {
                  print "DEBUG: RaGenerateSearchTerms: selects type $type obj $obj\n" if $debug;

                  if (length($sterm) == 0) {
                     $sterm = $sterm . "WHERE ";
                  } else {
                     $sterm = $sterm . " and ";
                  }
                  my ($tcol, $tobj) = RaReturnObject($type,$srchobj,$obj,$dbase);
                  if ( $tobj =~ m/\%/ ) {
                     $sterm = $sterm . "$tcol LIKE '$tobj'";
                  } else {
                     $sterm = $sterm . "$tcol = '$tobj'";
                  }
               }
            }
         }
         push @sterms, [$database, $dm, $object, $sterm, $stime];
      }
   }

   my $nterms = scalar @sterms;
   print "DEBUG: RaGenerateSearchTerms: dbase $database ($nterms) select terms.\n" if $debug;
   return @sterms;
}

sub RaGenerateSQLStatement {
   my ($table, $sterms) = @_;
   my $sql = "";

   switch ($database) {
      case "ether" {
         if (defined $table) {
            switch ($object) {
               case "Hosts" {
                  $sql = "SELECT COUNT(DISTINCT smac) FROM $table $sterms";
               }
               case "Pcr" {
                  $sql = "SELECT AVG(pcr) FROM $table $sterms";
               }
               case "Pkts" {
                  $sql = "SELECT SUM(spkts + dpkts) FROM $table $sterms";
               }
               case "Bytes" {
                  $sql = "SELECT SUM(sbytes + dbytes) FROM $table $sterms";
               }
               case "Trans" {
                  $sql = "SELECT SUM(trans) FROM $table $sterms";
               }
               case "Etype" {
                  $sql = "SELECT COUNT(DISTINCT etype) FROM $table $sterms";
               }
               case "Ethers" {
                  if (length($sterms) == 0) {
                     $sterms="WHERE smac!=\"\"";
                  }
                  $sql = "SELECT COUNT(DISTINCT smac) FROM $table $sterms";
               }
               case /^Ndegree/ {
                  if (length($sterms)) {
                     my $ssterms = $sterms;
                     my $dsterms = $sterms;
                     $dsterms =~ s/WHERE //;
                     $dsterms =~ s/smac/dmac/;
                     $sql = "SELECT COUNT(*) FROM etherMatrix.$table $ssterms or $dsterms";
                  } else {
                     $sql = "SELECT AVG( t1.c ) AS avgcol FROM (SELECT smac,count(*) AS c FROM etherMatrix.$table GROUP BY smac) t1";
                  }
               }
            }
         }
      }

      case "hostsInventory" {
         if (defined $table) {
            switch ($object) {
               case /^Ndegree/ {
                  if ($sterms =~ /addr/) {
                     $sql = "SELECT AVG(count) FROM $table $sterms";
                  } else {
                     my $itable = "inventory.".$table;
                     $itable =~ s/host/ipAddrs/;

                     $sql = "SELECT AVG(count) FROM $table WHERE (saddr IN ( SELECT saddr FROM $itable $sterms)) ";
                  }
                  if ( defined $mode ) {
                     if (length($sql) > 0) {
                       $sql .= " and ";
                     }
                     $sql .= "(region = '".$mode."')";
                  }
                  $sql .= " group by saddr;";
                  print "DEBUG: RaGenerateSQLStatement: '$sql'\n" if $debug;
               }
            }
         }
      }
      case "portsInventory" {
         if (defined $table) {
            switch ($object) {
               case "Ports" {
                  if ($sterms =~ /addr/) {
                     $sterms =~ s/[sd]addr/addr/g;
                     $sql = "SELECT tcp+udp FROM $table $sterms";
                  } else {
                     my $itable = "inventory.".$table;
                     $itable =~ s/...Ports/ipAddrs/;

                     $sql = "SELECT tcp+udp FROM $table WHERE addr IN ( SELECT saddr FROM $itable $sterms) group by addr;";
                  }
                  print "DEBUG: RaGenerateSQLStatement: '$sql'\n" if $debug;
               }
            }
         }
      }
      case /^policy/ {
         if (defined $table) {
            switch ($object) {
               case "aup" {
                  $sql = "SELECT * FROM $table $sterms";
               }
            }
         }
      }
      case /^inventory/ {
         if (defined $table) {
            switch ($object) {
               case "Senuuid" {
                  $sql = "SELECT COUNT(DISTINCT saddr) FROM $table $sterms";
               }
               case "Senid" {
                  $sql = "SELECT COUNT(DISTINCT saddr) FROM $table $sterms";
               }
               case "Etype" {
                  $sql = "SELECT COUNT(DISTINCT etype) FROM $table $sterms";
               }
               case "Ethers" {
                  if (length($sterms) == 0) {
                     $sterms="WHERE smac!=\"\"";
                  }
                  $sql = "SELECT COUNT(DISTINCT smac) FROM $table $sterms";
               }
               case "Countries" {
                  $sql = "SELECT COUNT(DISTINCT sco) FROM $table $sterms";
               }
               case "Servers" {
                  $sql = "SELECT COUNT(DISTINCT daddr) FROM $table $sterms";
               }
               case "Clients" {
                  $sql = "SELECT COUNT(DISTINCT saddr) FROM $table $sterms";
               }
               case "Pairs" {
                  switch ($database) {
                     case "ntpMatrix"   { $sql = "SELECT COUNT(*) FROM $table $sterms"; }
                     case "ipMatrix"    { $sql = "SELECT COUNT(*) FROM $table $sterms"; }
                     case "etherMatrix" { $sql = "SELECT COUNT(*) FROM $table $sterms"; }
                     else               { $sql = "SELECT COUNT(DISTINCT saddr) FROM $table $sterms"; }
                  }
               }
               case "Hosts" {
                  $sql = "SELECT COUNT(DISTINCT saddr) FROM $table $sterms";
               }
               case "Pcr" {
                  $sql = "SELECT AVG(pcr) FROM $table $sterms";
               }
               case "Ports" {
                  $sql = "SELECT AVG(tcp+udp) FROM $table $sterms";
               }
               case "Pkts" {
                  $sql = "SELECT SUM(spkts + dpkts) FROM $table $sterms";
               }
               case "Bytes" {
                  $sql = "SELECT SUM(sbytes + dbytes) FROM $table $sterms";
               }
               case /^Ndegree/ {
                  $sql = "SELECT COUNT(*) FROM $table $sterms";
               }
               case "Trans" {
                  $sql = "SELECT SUM(trans) FROM $table $sterms";
               }
            }
         }
      }
      case "etherMatrix"  {
         $sterms = "";
         if ((scalar @selectItems) > 0) {
            foreach my $sobj (@selectItems) {
               my ($type, $srchobj, $obj, $dbase) = @$sobj;
               if (length($type) > 0) {
                  print "DEBUG: RaGenerateSearchTerms: selects type $type obj $obj\n" if $debug;
                  if (length($sterms) == 0) {
                     $sterms = $sterms . "WHERE ";
                  } else {
                     $sterms = $sterms . " and ";
                  }

                  if (index($obj, "+") != -1) {
                     my ($col, $tobj) = RaReturnObject($type,$srchobj,$obj,$dbase);

                     if ((defined $srchobj) && (length($srchobj) > 0)) {
                        $col = $srchobj;
                     }
                     print "DEBUG: RaGenerateSearchTerms: search type $type obj $obj col $col tobj $tobj\n" if $debug;

                     my @orobj = split('\+', $obj);
                     my $cnt = 0;

                     if ($tobj =~ m/\%/ ) {
                        $sterms = $sterms . "( ";
                        foreach my $oobj (@orobj) {
                           my ($tcol, $tobj) = RaReturnObject($type,$srchobj,$oobj,$dbase);

                           if ($cnt > 0) { $sterms = $sterms . " or "; }
                           $sterms = $sterms . "$tcol LIKE '$tobj'";
                           $cnt++;
                        }
                        $sterms = $sterms . ")";
                     } else {
                        $sterms = $sterms . "$col IN (";
                        foreach my $oobj (@orobj) {
                           my ($tcol, $tobj) = RaReturnObject($type,$srchobj,$oobj,$dbase);

                           if ($cnt > 0) { $sterms = $sterms . ","; }
                           $sterms = $sterms . "'$tobj'";
                           $cnt++;
                        }
                        $sterms = $sterms . ")";
                     }
                  } else {
                     my ($tcol, $tobj) = RaReturnObject($type,$srchobj,$obj,$dbase);
                     if ((defined $srchobj) && (length($srchobj) > 0)) {
                        $tcol = $srchobj;
                     }
                     if ( $tobj =~ m/\%/ ) {
                        $sterms = $sterms . "$tcol LIKE '$tobj'";
                     } else {
                        $sterms = $sterms . "$tcol = '$tobj'";
                     }
                  }
               }
            }
         }
         $sql = "SELECT COUNT(*) FROM $table $sterms";
      }

      case "ipMatrix"  {
         $sql = "SELECT COUNT(*) FROM $table $sterms";
      }
      case "arpMatrix" {
         $sql = "SELECT COUNT(DISTINCT $field) FROM $table $sterms";
      }
      case "dnsMatrix" {
         $sql = "SELECT COUNT(DISTINCT $field) FROM $table $sterms";
      }
      case "ntpMatrix" {
         $sql = "SELECT COUNT(DISTINCT $field) FROM $table $sterms";
      }
      case "imapsMatrix" {
         $sql = "SELECT COUNT(DISTINCT $field) FROM $table $sterms";
      }
      case "dhcpMatrix" {
         $sql = "SELECT COUNT(DISTINCT $field) FROM $table $sterms";
      }
      case "httpMatrix" {
         $sql = "SELECT COUNT(DISTINCT $field) FROM $table $sterms";
      }
      case "smtpMatrix" {
         $sql = "SELECT COUNT(DISTINCT $field) FROM $table $sterms";
      }
      case "ldapMatrix" {
         $sql = "SELECT COUNT(DISTINCT $field) FROM $table $sterms";
      }
      case "dnsNames"  {
         switch ($object) {
            case "Names" {
               if (length($sterms)) {
                  $sql =  "SELECT ((LENGTH(REGEXP_SUBSTR(names, '\"auth\": \\\\[[^\\]]+'))) - LENGTH(REPLACE(REGEXP_SUBSTR(names, '\"auth\": \\\\[[^\\]]+'), ',', '' )) + 1) FROM $table $sterms";
               } else {
                  $sql =  "SELECT ((LENGTH(REGEXP_SUBSTR(names, '\"auth\": \\\\[[^\\]]+'))) - LENGTH(REPLACE(REGEXP_SUBSTR(names, '\"auth\": \\\\[[^\\]]+'), ',', '' )) + 1) FROM $table";
               }
            } else {
               $sql = "SELECT COUNT(DISTINCT addr) FROM $table $sterms";
            }
         }
      }
      case "dnsAddrs"  {
         switch ($object) {
            case "TLDs" {
               $sql = "SELECT COUNT(DISTINCT tld) FROM $table $sterms";
            }
            case "Domains" {
               $sql = "SELECT COUNT(DISTINCT nld) FROM $table $sterms";
            }
            case "Names" {
               $sql = "SELECT COUNT(DISTINCT name) FROM $table $sterms";
            }
            case "Hosts" {
               if (length($sterms)) {
                  $sql = "SELECT (LENGTH(addrs) - LENGTH(REPLACE(addrs, ',', '')) + 1) FROM $table $sterms";
               } else {
                  $sql = "SELECT COUNT(DISTINCT name) FROM $table $sterms";
               }
            } else {
               $sql = "SELECT COUNT(DISTINCT name) FROM $table $sterms";
            }
         }
      }
      case "scanners"  {
         if (defined $mode) {
            if (index($table, $mode) != -1) {
               $sql = "SELECT COUNT(DISTINCT saddr) FROM $table $sterms";
            }
         } else {
            $sql = "SELECT COUNT(DISTINCT saddr) FROM $table $sterms";
         }
      }
      case "Sen_Notifications"  {
         switch ($object) {
            case [ "Esoc", "esoc"] {
               $sql = "SELECT from_unixtime(stime, '%Y-%m-%d') Date, COUNT(*) Value FROM DHS_ESOC group by from_unixtime(stime, '%Y-%m-%d');";
            } else {
               $sql = "SELECT uuid,id,score,stime,lhtime,ctime,ipWatchList,domainWatchList,alreadyBlockedBlue,alreadyBlockedEsoc,clique FROM $table $sterms";
            }
         }
      }
      case /^status/ {
         switch ($object) {
            case "Logs" {
               $sql = "SELECT * FROM $table $sterms";
            }
         }
      }
   }

   if (length($sql) > 0) {
   }
   return $sql;
}

sub RaCliqueGetTables {
   my $dbase = shift;
   my $stime = shift;
   my $etime = shift;

   my $dates = 1;
   my $tableFormat;
   my @tables = ();
   my %hash = {};

   $dbh->do("use $dbase;");

   my $sth = $dbh->prepare("show tables;");
   $sth->execute();
   while(my @row = $sth->fetchrow_array()) {
      $hash{@row[0]}++;
   }
   $sth->finish();

   switch ($dbase) {
      case "inventory"         { $tableFormat = "ipAddrs"; }
      case "ether"             { $tableFormat = "ether"; }
      case "dnsAddrs"          { $tableFormat = "dns"; }
      case "dnsNames"          { $tableFormat = "dns"; }
      case "ipMatrix"          { $tableFormat = "ip"; }
      case "etherMatrix"       { $tableFormat = "ether"; }
      case "ntpMatrix"         { $tableFormat = "ntp"; }
      case "arpMatrix"         { $tableFormat = "arp"; }
      case "dnsMatrix"         { $tableFormat = "dns"; }
      case "ldapMatrix"        { $tableFormat = "ldap"; }
      case "imapsMatrix"       { $tableFormat = "imaps"; }
      case "hostsInventory"    { $tableFormat = "host"; }
      case "scanners"          { $tableFormat = $mode; }
      else                     { $dates = 0; }
   }

   print "DEBUG: RaCliqueGetTables: db $dbase table $tableFormat stime $stime etime $etime\n" if $debug;

   if ($dates) {
#
#     Issue with crossing a daylight savings time boundary.
#     Times should be 00:00:00 times, if not, then adjust so that they are.
# 
      while ($stime <= $etime) {
         my @tnames = split(',', $tableFormat);
         my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($stime);

         if ($hour != 0) {
            if ($hour == 23) {
               $stime += 3600;
            } else {
               $stime -= 3600;
            }
            ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($stime);
         }

         my $date = sprintf("%4d-%02d-%02d", $year+1900, $mon + 1, $mday);

         my $val = scalar @tinds;
         my ($mch) = grep { $tinds[$_] eq $wday } (0 .. @tinds-1);

         if (($val == 0) || defined $mch) {
            foreach my $tab (@tnames) {
               my $tableName = sprintf("%s_%4d_%02d_%02d", $tab, $year+1900, $mon + 1, $mday);

               if ($hash{$tableName} > 0) {
                  my @trow = ($date, $tableName, $tab);
                  push @tables, \@trow;
               }
            }
         }
         $stime += 86400;
      }
   }

   my $tlen = scalar @tables;
   print "DEBUG: RaCliqueGetTables: found $tlen tables\n" if $debug;
   return @tables;
}

sub RaCliqueFetchData {
   my $file = shift;
   my $ctime = shift;
   $clique = shift;

   my %dateHash = ();
   my $deferred = 0;
   my @tables;
   my @columns;

   if (defined($database)) {
      print "DEBUG: RaCliqueFetchData: db:$database dm:$dm ob:$object mode:$mode filter:'$filter'\n" if $debug;
      my @sarray = RaGenerateSearchTerms($file);
      my $sterms;

      if ($clique) {
         my $cal = decode_json $clique;
         foreach my $tr (@$cal) {
            $dateHash{$tr->{Date}} = $tr->{Value};
         }
         print $fh "RaCliqueFetchData: using cached clique data ctime:$ctime stime:$stime\n";
         print "DEBUG: RaCliqueFetchData: using cached clique data ctime:$ctime stime:$stime\n" if $debug;
      }

      foreach my $ar (@sarray) {
         ($database, $dm, $object, $sterms, $stime) = @$ar;

         if ($ctime > $stime) {
            $stime = $ctime;
         }

         print "DEBUG: RaCliqueFetchData: database:$database sterms:'$sterms'\n" if $debug;
         print $fh "RaCliqueFetchData: db:$database dm:$dm ob:$object stime:$stime sterms:'$sterms'\n";

         @tables = RaCliqueGetTables($database, $stime, $etime);

         switch ($dm) {
            case [ "etype", "ether", "inventory", "dnsAddrs", "hostsInventory", "portsInventory" ] {
               @columns = ("Date", "Value");
               my $m = $mode;

               $deferred = 1;
               foreach my $tr (@tables) {
                 my $date = $tr->[0];
                 my $table = $tr->[1];
                 my $tmode = $tr->[2];
                 my $found = 0;
                 my @row;

                 if ($database eq "scanners") {
                    $mode = $tmode;
                 }

                 if ($dm eq "dnsAddrs") {
                   my $ssql = "SELECT t1.name FROM $table t1 INNER JOIN dnsNamesTable t2 ON ((t1.name = t2.name) or (t1.name LIKE CONCAT('%.', t2.name)))";

                   my $ssth = $dbh->prepare($ssql);

                   $ssth->execute();
                   while (my @res = $ssth->fetchrow_array) {
                     $found++;
                     print "DEBUG: RaCliqueFetchData: domain match sql '$ssql'\n" if $debug;
                   }
                   if ($found > 0) {
                      $row[0] = $date;
                      $row[1] = "$found";
                      $dateHash{$row[0]} += $row[1];
                      print "DEBUG: RaCliqueFetchData: found: domain match sql $row[0], $row[1]\n" if $debug;
                   }
                   $ssth->finish();

                 } else {
                   my $ssql = RaGenerateSQLStatement($table, $sterms);

                   if (length($ssql) > 0) {
                     my $ssth = $dbh->prepare($ssql);
                     print "DEBUG: RaCliqueFetchData: sql:'$ssql'\n" if $debug;
                     $ssth->execute();

                     if (my @res = $ssth->fetchrow_array()) {
                        $found = $res[0];
                        if ($found != 0) {
                           $row[0] = $date;
                           $row[1] = "$found";
                           $dateHash{$row[0]} = $row[1];
                        }
                     }
                     $ssth->finish();
                   }
                 }
               }
               $mode = $m;
            }

            case [ "Esoc", "esoc" ] {
               my $table = '';
               @columns = ("Date", "Value", "Score");

               if (defined $dbh) {
                  $dbh->do("use $database");

                  my %values = ();
                  my $ssql = RaGenerateSQLStatement($table, $sterms);
                  my $score;
                  my @row;

                  if (length($ssql) > 0) {
                     print "DEBUG: RaCliqueFetchData: Select SQL: $ssql\n" if $debug;
                     my $sth = $dbh->prepare($ssql);
                     $sth->execute();

                     while (my $hashref = $sth->fetchrow_hashref()) {
                        push($results_ref, $hashref);
                     }
                     $sth->finish();
                  }
               }
            }

            case [ "policy", "ruleset", "rules" ] {
               my $table = '';
               @columns = ("Date", "Value", "Score");

               switch ($object) {
                  case "aup" {
                     $table = "aup";
                  }
               }


               if (defined $dbh) {
                  $dbh->do("use $database"); 

                  my %values = ();
                  my $ssql = RaGenerateSQLStatement($table, $sterms);
                  my $score;
                  my @row;

                  if (length($ssql) > 0) {
                     print "DEBUG: RaCliqueFetchData: Select SQL: $ssql\n" if $debug;
                     my $sth = $dbh->prepare($ssql);
                     $sth->execute();

                     while (my $hashref = $sth->fetchrow_hashref()) {
                        my $stime = $hashref->{'stime'};
                        my $policy = $hashref->{'policy'};
                        my $version = $hashref->{'version'};
                        my $name = $hashref->{'name'};

                        my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = localtime($stime);
                        my $date = sprintf( "%04d-%02d-%02d", $year+1900, $mon+1, $mday);

                        if ($hashref->{'nonconform'} > 0) {
                           $score = 11; 
                        } elsif ($hashref->{'verify'} != $hashref->{'match'}) {
                           $score = 9; 
                        } else {
                           $score = 4; 
                        }
                        $values{$date}{$policy}{$version}{$name}{'match'}  += $hashref->{'match'};
                        $values{$date}{$policy}{$version}{$name}{'score'}   = $score;
                     }
                     $sth->finish();
                  }

                  switch ($dm) {
                     case "policy" {
                        foreach my $date (keys %values) {
                           foreach my $policy (keys $values{$date}) {
                              $values{$date}{count}++;
                              foreach my $name (keys $values{$date}{$policy}) {
                                 foreach my $version (keys $values{$date}{$policy}{$name}) {
                                    if ($values{$date}{score} < $values{$date}{$policy}{$name}{$version}{'score'}) {
                                       $values{$date}{score} = $values{$date}{$policy}{$name}{$version}{'score'};
                                    }
                                 }
                              }
                           }
                        }

                     }
                     case "ruleset" {
                        foreach my $date (keys %values) {
                           foreach my $policy (keys $values{$date}) {
                              foreach my $version (keys $values{$date}{$policy}) {
                                 $values{$date}{count}++;
                                 foreach my $name (keys $values{$date}{$policy}{$version}) {
                                    if ($values{$date}{score} < $values{$date}{$policy}{$version}{$name}{'score'}) {
                                       $values{$date}{score} = $values{$date}{$policy}{$version}{$name}{'score'};
                                    }
                                 }
                              }
                           }
                        }

                     }
                     case "rules" {
                        foreach my $date (keys %values) {
                           foreach my $policy (keys $values{$date}) {
                              foreach my $version (keys $values{$date}{$policy}) {
                                 foreach my $name (keys $values{$date}{$policy}{$version}) {
                                    $values{$date}{count}++;
                                    if ($values{$date}{score} < $values{$date}{$policy}{$version}{$name}{'score'}) {
                                       $values{$date}{score} = $values{$date}{$policy}{$version}{$name}{'score'};
                                    }
                                 }
                              }
                           }
                        }
                     }
                  }
                  foreach my $date (keys %values) {
                     foreach my $policy (keys $values{$date}) {
                        my @row = ( $date, $values{$date}{count}, $values{$date}{score} );
                        my %r;
                        @r{@columns} = @row;
                        push($results_ref, \%r);
                     }
                  }
               }
            }

            case /^sensors/ {
               my $rasql       = which 'rasql';
               my $rabins      = which 'rabins';
               my $fields      = "node sid  time trans";
               my $ra;

               my $info;
               my @stages;

               push @stages, "$rasql -t $time -r 'mysql://root\@localhost/$database/sensors' -w - $filter";
               if (defined $search) {
                  push @stages, "$rabins -m sid inf -M time 1d -M dsrs='-agr,-suser,-duser' -r - -w - - sid $search";
               } else {
                  push @stages, "$rabins -m sid inf -M time 1d -M dsrs='-agr,-suser,-duser' -r - -w - ";
               }
               push @stages, "$rabins -XF conf/ra.local.conf -m all -M time 1d -M dsrs='-agr' -r - -s $fields -M json";
               $ra = join(" | ", @stages);

               $ra = "$ra > '$file'";
               print "DEBUG: RaInventoryFetchData: cmd: $ra\n" if $debug;

               print $fh "RaCliqueFetchData: db $database dm $dm ob $object filter '$filter' search '$search' sterms '$sterms' \n";
               print $fh "$ra\n";
               system($ra);

               chmod 0644, $file;
               open $info, $file;
               @columns = ("Date", "Value");

               while( my $data = <$info>) {
                  chomp($data);
                  if (length($data)) {
                    print "DEBUG: RaInventoryFetchData: $data\n" if $debug;
                    my $decoded = decode_json $data;
                    my @row = [];
                    $row[0] = $decoded->{'stime'};
                    $row[1] = $decoded->{'trans'};

                    $row[0] =~ s/\//-/g;
                           
                    my %r;
                    @r{@columns} = @row;
                    push($results_ref, \%r);
                  }
               }
            }
            case /^site/ {
               my $table = '';
               @columns = ("Date", "Value", "Score");

               switch ($object) {
                  case "System" {
                     $table = "site_logs_status";
                  }
                  case "Logs" {
                     $table = "site_logs_status";
                  }
                  case "Storage" {
                     $table = "site_logs_status";
                  }
               }

               print $fh "RaCliqueFetchData: db $database dm $dm ob $object filter '$filter' search '$search'\n";

               if (defined $dbh) {
                  $dbh->do("use $database"); 

                  my $ssql = RaGenerateSQLStatement($table, $sterms);
                  my $score;

                  if (length($ssql) > 0) {
                     print "DEBUG: RaCliqueFetchData: Select SQL: $ssql\n" if $debug;
                     my $sth = $dbh->prepare($ssql);
                     $sth->execute();
                     while (my $hashref = $sth->fetchrow_hashref()) {
                        my @row = [];
                        my $stime = $hashref->{'stime'};
                        print "DEBUG: RaCliqueFetchData: stime $stime\n" if $debug;
                        my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = localtime($stime);
                        my $date = sprintf( "%04d-%02d-%02d", $year+1900, $mon+1, $mday);
                        $row[0] = $date;
                        $row[1] = $hashref->{'emerg'} + $hashref->{'alert'} + $hashref->{'crit'} + $hashref->{'error'} + $hashref->{'warn'} + $hashref->{'notice'} + $hashref->{'info'};
                        if ($hashref->{'emerg'} || $hashref->{'crit'}) { 
                           $score = 15; 
                        } elsif ($hashref->{'error'} || $hashref->{'warn'}) {
                           $score = 8; 
                        } else {
                           $score = 0; 
                        }
                        $row[2] = $score;

                        my %r;
                        @r{@columns} = @row;
                        push($results_ref, \%r);
                     }
                     $sth->finish();
                  }
               }
            }
         }
      }

      if ($deferred) {
         foreach my $date (keys %dateHash) {
            my @row;
            my %r;
            $row[0] = $date;
            $row[1] = $dateHash{$date};

            @r{@columns} = @row;
            push($results_ref, \%r);
         }
      }
   }
}

sub RaCliqueGenerateOutput {
   my $clique = encode_json $results_ref;

   my $now = time();

   if (!$quiet) {
      if ($web) {
         print header(-type=>'application/json');
      }
      print $clique;
      print "\n";
   }
}

sub RaCliqueCleanUp {
   my $file = shift;

   print "DEBUG: calling RaCliqueCleanUp\n" if $debug;
   unlink $file;
}

sub RaCliqueGetStartTime {
   my $etime = shift;
   my $stime = 0;
   my ($interval) = $time =~ /(\d+)/;

   my $scale = substr $time, -1;
   $interval =~ /(\d+)/;

   switch ($scale) {
      case "s" {
         my $inc = ($interval);
         $stime = $etime - $inc;
         print "DEBUG: RaCliqueGetStartTime: scale $scale interval $interval stime $stime etime $etime\n" if $debug;
      }
      case "m" {
         my $inc = ($interval*60);
         $stime = $etime - $inc;
         print "DEBUG: RaCliqueGetStartTime: scale $scale interval $interval stime $stime etime $etime\n" if $debug;
      }
      case "h" {
         my $inc = ($interval*60*60);
         $stime = $etime - $inc;
         print "DEBUG: RaCliqueGetStartTime: scale $scale interval $interval stime $stime etime $etime\n" if $debug;
      }
      case "d" {
         my $inc = ($interval*60*60*24);
         $stime = $etime - $inc;
         print "DEBUG: RaCliqueGetStartTime: scale $scale interval $interval stime $stime etime $etime\n" if $debug;
      }
   }
   return $stime;
}

exit 0;

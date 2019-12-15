use mysql;

drop function if exists rasql_udf_cidr_info;
drop function if exists str_numtowords;
drop function if exists rasql_compareCidrtoAddr;

create function rasql_udf_cidr_info returns string soname 'rasql_udf_cidr.so';
create function str_numtowords returns string soname 'rasql_udf_cidr.so';
create function rasql_compareCidrtoAddr returns integer soname 'rasql_udf_cidr.so';

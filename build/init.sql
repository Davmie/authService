

drop table if exists Tokens cascade;
create table public.Tokens(
                              id serial not null primary key,
                              userid varchar(20) not null,
                              refresh_token text not null unique,
                              client_ip varchar(20) not null
);

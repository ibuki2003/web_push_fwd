create table registrations (
    id varchar(255) not null,
    token varchar(255) not null,
    domain varchar(255) not null,
    vapid varchar(255) not null,
    primary key (id),
    index index_token_domain (token, domain)
);


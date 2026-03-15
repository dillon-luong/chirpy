-- +goose Up
create table users(
    id UUID primary key,
    created_at timestamp not null,
    updated_at timestamp not null,
    email text unique not null,
    hashed_password text not null default 'unset'
);

-- +goose Down
drop table users;
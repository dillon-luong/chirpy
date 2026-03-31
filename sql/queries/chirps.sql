-- name: CreateChirp :one
insert into chirps (id, created_at, updated_at, body, user_id)
values (
    gen_random_uuid(),
    now(),
    now(),
    $1,
    $2
)
returning *;

-- name: GetAllChirps :many
select * from chirps
order by created_at asc;

-- name: GetChirp :one
select * from chirps
where id=$1;

-- name: DeleteChirp :exec
delete from chirps
where id = $1 and user_id = $2;

-- name: CountUserChirps :one
select count(*) from chirps
where id = $1 and user_id = $2;
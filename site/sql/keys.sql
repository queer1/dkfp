CREATE TABLE keys (
    id integer primary key,
    domain text not null,
    selector text not null,
    txtrecord text not null,
    first_seen datetime not null,
    last_seen datetime,
    notes text,
    compromised boolean default false
);

CREATE TABLE reputation (
    id integer primary key,
    key_id integer not null,
    reputation integer not null,
    t datetime not null default current_timestamp,
    foreign key(key_id) references keys(id)
);



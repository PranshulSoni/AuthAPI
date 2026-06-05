import * as db from 'pg';

export function createPool(config:db.PoolConfig):db.Pool{
    const pool=new db.Pool(config);
    return pool;
}   

import test from "node:test";
import assert from "node:assert/strict";
import {create} from "../src/host_facilities/state.mjs";
function fixture(){const seen={sessions:[],calls:0};const session={prepare(sql){return {sql,bind(...params){this.params=params;return this;}};},async batch(statements){seen.calls++;return statements.map(()=>({success:true,results:[{active:1}],meta:{changes:0}}));}};return {seen,withSession(mode){seen.sessions.push(mode);return session;}};}
function scope(){return {closed:false,async run(work){if(this.closed)throw new Error("event_closed");const value=await work();if(this.closed)throw new Error("event_closed");return value;}};}
test("source-selected exact named primary binding, bounded batch and closed event",async()=>{const db=fixture(),lease=scope(),binding=create(db,lease,{profile:"workers-d1",binding:"OWNER_DB"});assert.equal(binding.name,"OWNER_DB");const input=JSON.stringify([{sql:"SELECT active FROM owned_credential",params:[]}]);const result=JSON.parse(await binding.batch(input));assert.deepEqual(result[0].results,[{active:1}]);assert.deepEqual(db.seen.sessions,["first-primary"]);await assert.rejects(binding.batch("[]"));assert.equal(db.seen.calls,1);lease.closed=true;await assert.rejects(binding.batch(input),/event_closed/);assert.equal(db.seen.calls,1);});
test("wrong profile or malformed binding and unknown replies fail closed",async()=>{const db=fixture();assert.throws(()=>create(db,scope(),{profile:"native-pg",binding:"DB"}));assert.throws(()=>create(db,scope(),{profile:"workers-d1",binding:"bad/binding"}));assert.throws(()=>create({...db,withSession:undefined},scope(),{profile:"workers-d1",binding:"DB"}));let calls=0;const binding=create({withSession(){return {prepare(){return {bind(){return {};}};},async batch(){calls++;throw new Error("lost_commit_reply");}};}},scope(),{profile:"workers-d1",binding:"DB"});await assert.rejects(binding.batch(JSON.stringify([{sql:"UPDATE owned_record SET active=0",params:[]}])));assert.equal(calls,1);});

test("a later admission in the same event sees a concurrent primary revocation",async()=>{
 let active=1,sessions=0;
 const database={withSession(mode){assert.equal(mode,"first-primary");sessions++;const primarySnapshot=active;return {prepare(sql){return {sql,bind(){return this;}};},async batch(statements){return statements.map(()=>({success:true,results:[{active:primarySnapshot}],meta:{changes:0}}));}};}};
 const binding=create(database,scope(),{profile:"workers-d1",binding:"OWNER_DB"});
 const input=JSON.stringify([{sql:"SELECT active FROM owned_authority",params:[]}]);
 assert.equal(JSON.parse(await binding.batch(input))[0].results[0].active,1);
 active=0;
 assert.equal(JSON.parse(await binding.batch(input))[0].results[0].active,0);
 assert.equal(sessions,2);
});

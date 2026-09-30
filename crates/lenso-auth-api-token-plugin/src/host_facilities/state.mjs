// Private Owner SQL transport. The Host selects one binding and one event scope.
export function create(database,scope,configuration){
 const name=configuration?.binding;
 if(configuration?.profile!=="workers-d1"||typeof name!=="string"||!/^[A-Za-z][A-Za-z0-9_]{0,127}$/.test(name)||typeof database?.withSession!=="function"||typeof scope?.run!=="function")throw new Error("invalid_auth_d1_facility");
 return Object.freeze({name,batch:input=>scope.run(async()=>{
  const statements=JSON.parse(input);
  if(!Array.isArray(statements)||!statements.length||statements.length>128||statements.some(s=>typeof s.sql!=="string"||!Array.isArray(s.params)||s.params.length>100))throw new Error("invalid_auth_batch");
  const session=database.withSession("first-primary");
  const result=await session.batch(statements.map(s=>session.prepare(s.sql).bind(...s.params)));
  if(!Array.isArray(result)||result.length!==statements.length||result.some(r=>!r.success||!Array.isArray(r.results)))throw new Error("invalid_auth_receipt");
  return JSON.stringify(result);
 })});
}

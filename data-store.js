/* Application data stays in Firestore. Only account operations call Functions. */
'use strict';
globalThis.maintenanceData = (() => {
  const F = firebase.firestore.FieldValue;
  const authCalls = {adminLogin:'maintenanceAdminLogin',adminSession:'maintenanceAdminSession'};
  const invoke = async (name,data={}) => (await backend.httpsCallable(authCalls[name] || name)(data)).data;
  const requests = () => db.collection('repairJobs');
  const privatePins = () => db.collection('_requestPins');
  const auditRef = () => db.collection('adminLogs').doc();
  const now = () => new Date().toISOString();
  const copy = value => JSON.parse(JSON.stringify(value));
  const fail = message => {throw new Error(message);};
  async function actor(superOnly=false) {
    const user=auth.currentUser;
    if(!user) fail('กรุณาเข้าสู่ระบบแอดมิน');
    const claims=(await user.getIdTokenResult()).claims;
    const role=claims.adminRole;
    if(!['super','limited'].includes(role)||user.uid!=='maintenance-'+role) fail('กรุณาเข้าสู่ระบบแอดมิน');
    if(superOnly&&role!=='super') fail('ทำได้เฉพาะ Admin ใหญ่');
    return {uid:user.uid,role};
  }
  function jobDefaults(data,jobId) {
    return {jobID:jobId,requestDate:now(),requesterName:'',positionDept:'',phoneNumber:'',equipId:'',equipmentLocation:'',problemDetails:'',urgency:'Low',status:'Waiting',imageBefore:'',imageAfter:'',technician:'',adminRemarks:'',additionalNotes:'',cost:0,itemsData:'[]',...data,jobID:jobId};
  }
  function entry(who,action,target,before,after,extra={}) {
    return {kind:'job',actor:who,action,target,before,after,timestamp:F.serverTimestamp(),...extra};
  }
  async function jobWrite({jobId,patch={},mode='update',action}) {
    const who=await actor(mode!=='complete');
    if(!['update','set','delete','complete'].includes(mode)) fail('การทำรายการไม่ถูกต้อง');
    const ref=requests().doc(jobId), log=auditRef();
    const input={...patch}; const pin=input.userPin; delete input.userPin;
    if(mode!=='set'&&pin!==undefined) fail('เปลี่ยน PIN ผ่านรายการนี้ไม่ได้');
    return db.runTransaction(async tx => {
      const snap=await tx.get(ref); if(!snap.exists&&mode!=='set') fail('ไม่พบใบงาน');
      const before=snap.exists?snap.data():{};
      let data={...input};
      if(mode==='complete') {
        if(!canCompleteJob(before)) fail('สถานะงานเปลี่ยนแล้ว กรุณารีเฟรช');
        const time=now();data={status:'Done',completedDate:time,techDoneDate:time};
        if(!before.acceptedDate)data.acceptedDate=time;
      }
      if(data.jobID!==undefined&&data.jobID!==jobId) fail('เปลี่ยนเลขใบงานไม่ได้');
      let after=mode==='delete'?{}:mode==='set'?jobDefaults(data,jobId):{...before,...data};
      if(mode!=='delete') {
        after.lastAdminLogId=log.id;after.lastModifiedBy=who;after.lastModifiedAt=now();
      }
      const operation=mode==='delete'?'delete':snap.exists?'update':'create';
      if(mode==='delete') {
        tx.set(db.collection('_jobDeletions').doc(jobId),{logId:log.id,uid:who.uid,timestamp:F.serverTimestamp()});
        tx.delete(ref);tx.delete(privatePins().doc(jobId));
      } else {
        tx.set(ref,after);
        if(mode==='set'&&pin!==undefined&&String(pin))tx.set(privatePins().doc(jobId),{pin:String(pin),requesterUid:after.requesterUid||''});
      }
      tx.set(log,entry(who,action||(mode==='complete'?'กดซ่อมเสร็จ':mode==='delete'?'ลบใบงาน':mode==='set'?'นำเข้าใบงานจาก Excel':'แก้ไขใบงาน'),jobId,before,after,{operation,pinChanged:mode==='set'&&!!pin}));
      return {changed:true};
    });
  }
  async function event({action,target=''}) {
    const who=await actor();
    if(['เปิดดู PIN ผู้แจ้ง','สร้างไฟล์รายงานรวม'].includes(action)&&who.role!=='super')fail('ทำได้เฉพาะ Admin ใหญ่');
    await auditRef().set({kind:'event',actor:who,action,target,timestamp:F.serverTimestamp()});
    return {ok:true};
  }
  async function configUpdate(input) {
    const who=await actor(true),ref=db.collection('system').doc('publicConfig'),log=auditRef();
    return db.runTransaction(async tx => {
      const snap=await tx.get(ref),before=snap.exists?snap.data():{};
      const patch={};
      if(input.jobIdConfig)patch.jobIdConfig=input.jobIdConfig;
      if(input.listChange) {
        const {type,act,value}=input.listChange;
        if(!['depts','techs'].includes(type)||!['add','del'].includes(act)||typeof value!=='string'||!value.trim()||value.length>120)fail('รายการตั้งค่าไม่ถูกต้อง');
        const lists=copy(before.lists||{depts:[],techs:[]});
        if(act==='add'&&lists[type].includes(value))return {changed:false};
        lists[type]=act==='add'?[...lists[type],value]:lists[type].filter(x=>x!==value);
        patch.lists=lists;patch.lastListChange={type,act,value};
      }
      const after={...before,...patch,lastAdminLogId:log.id};
      tx.set(ref,after);
      tx.set(log,{kind:'config',actor:who,action:input.listChange?'แก้ไขรายการตั้งค่า':'เปลี่ยนการตั้งค่าระบบ',target:'system/publicConfig',before,after,timestamp:F.serverTimestamp()});
      return {changed:true};
    });
  }
  async function createRequest(input) {
    const user=auth.currentUser;if(!user)fail('กรุณารอเชื่อมต่อแล้วลองใหม่');
    const token=(await user.getIdTokenResult()).claims;
    if(token.adminRole==='limited')fail('กรุณาออกจากระบบเพื่อทำรายการในฐานะผู้แจ้ง');
    if(!/^[0-9]{4,6}$/.test(String(input.userPin||'')))fail('PIN ต้องเป็นตัวเลข 4–6 หลัก');
    const cfg=(await db.collection('system').doc('publicConfig').get()).data()?.jobIdConfig||{prefix:'MTN',startNum:1};
    const year=new Intl.DateTimeFormat('en',{year:'numeric',timeZone:'Asia/Bangkok'}).format(new Date());
    const counterId=cfg.prefix+'-'+year;
    const counter=db.collection('_jobCounters').doc(counterId);
    const log=token.adminRole==='super'?auditRef():null;
    const who=log?await actor(true):null;
    return db.runTransaction(async tx => {
      const count=await tx.get(counter);
      const sequence=Math.max((count.data()?.last||0)+1,Number(cfg.startNum)||1);
      const jobId=counterId+'-'+String(sequence).padStart(4,'0'),ref=requests().doc(jobId);
      if((await tx.get(ref)).exists)fail('เลขใบงานซ้ำ กรุณาตรวจการเตรียมข้อมูลเริ่มต้น');
      const data={...input};delete data.userPin;delete data.status;
      const job=jobDefaults(data,jobId);
      Object.assign(job,{requesterUid:user.uid,counterId,sequence,status:'Waiting',requestDate:now()});
      if(log)Object.assign(job,{lastAdminLogId:log.id,lastModifiedBy:who,lastModifiedAt:now()});
      tx.set(counter,{last:sequence,jobId,uid:user.uid,updatedAt:F.serverTimestamp()});
      tx.set(ref,job);tx.set(privatePins().doc(jobId),{pin:String(input.userPin),requesterUid:user.uid});
      if(log)tx.set(log,entry(who,'สร้างใบแจ้งซ่อม',jobId,{},job,{operation:'create',pinChanged:true}));
      return {jobId};
    });
  }
  async function requesterAction(input) {
    const user=auth.currentUser;if(!user)fail('กรุณาเชื่อมต่อใหม่');
    const claims=(await user.getIdTokenResult()).claims;
    if(claims.adminRole==='limited')fail('กรุณาออกจากระบบเพื่อทำรายการในฐานะผู้แจ้ง');
    const who=claims.adminRole==='super'?await actor(true):null;
    const ref=requests().doc(input.jobId),proof=db.collection('_requestProofs').doc();
    const log=who?auditRef():null;
    await db.runTransaction(async tx => {
      const snap=await tx.get(ref);if(!snap.exists)fail('ไม่พบใบงาน');const before=snap.data();let patch;
      const time=now();
      if(input.action==='verify'){
        if(before.status!=='Done')fail('งานนี้ยังไม่พร้อมปิด');patch={status:'Closed',completedDate:time,ownerClosedDate:time};
      }else if(input.action==='unrepairable'){
        if(before.status!=='Unrepairable'||before.unrepairableConfirmedDate)fail('งานนี้ไม่อยู่ในสถานะรอยืนยัน');patch={unrepairableConfirmedDate:time};
      }else if(input.action==='cancel'){
        if(!canCompleteJob(before))fail('งานนี้ขอยกเลิกไม่ได้');patch={cancelRequest:{requestedDate:time,reason:input.reason||'แจ้งใหม่เป็นใบ '+input.refJobId,refJobId:input.refJobId||''}};
      }else fail('รายการไม่ถูกต้อง');
      const after={...before,...patch,lastRequesterProofId:proof.id};
      if(log)Object.assign(after,{lastAdminLogId:log.id,lastModifiedBy:who,lastModifiedAt:time});
      tx.set(proof,{jobId:input.jobId,pin:String(input.pin||''),action:input.action,uid:user.uid,createdAt:F.serverTimestamp()});
      tx.set(ref,after);
      if(log)tx.set(log,entry(who,'ผู้แจ้ง: '+input.action,input.jobId,before,after,{operation:'update',pinChanged:false}));
    });
    // Remove the temporary submitted PIN after Rules have validated the batch.
    await proof.delete().catch(()=>{});return {ok:true};
  }
  async function getPin(jobId) {
    await actor(true);await event({action:'เปิดดู PIN ผู้แจ้ง',target:jobId});
    const snap=await privatePins().doc(jobId).get();if(!snap.exists)fail('ไม่พบ PIN ของใบงาน');return {pin:snap.data().pin};
  }
  async function verifyAdmin(input) {
    await actor(true);
    if(input.password!==undefined){const result=await invoke('maintenanceAdminLogin',{password:input.password});if(result.actor?.role!=='super')fail('รหัส Admin ใหญ่ไม่ถูกต้อง');}
    if(input.pin!==undefined){const pin=await privatePins().doc(input.jobId).get();if(!pin.exists||String(input.pin)!==String(pin.data().pin))fail('PIN ผู้แจ้งไม่ถูกต้อง');}
    return {ok:true};
  }
  async function call(name,data={}) {
    if(name.startsWith('maintenanceAdmin')||authCalls[name])return invoke(name,data);
    if(name==='adminJobWrite')return jobWrite(data);
    if(name==='adminConfigUpdate')return configUpdate(data);
    if(name==='adminEvent')return event(data);
    if(name==='createRequest')return createRequest(data);
    if(name==='requesterAction')return requesterAction(data);
    if(name==='adminGetPin')return getPin(data.jobId);
    if(name==='adminVerify')return verifyAdmin(data);
    fail('ไม่รองรับการทำรายการนี้');
  }
  return {call};
})();

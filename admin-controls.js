// UI controls only. Firebase callable functions and rules enforce permissions.
"use strict";

function isSuperAdmin() {
  return appData.isAdmin && appData.adminRole === "super";
}

function requireAdmin() {
  if (appData.isAdmin && ["super", "limited"].includes(appData.adminRole))
    return true;
  Swal.fire("ไม่มีสิทธิ์", "กรุณาเข้าสู่ระบบแอดมิน", "warning");
  return false;
}

function requireSuperAdmin() {
  if (isSuperAdmin()) return true;
  Swal.fire("ไม่มีสิทธิ์", "รายการนี้ทำได้เฉพาะ Admin ใหญ่", "warning");
  return false;
}

async function callBackend(name, data = {}) {
  return maintenanceData.call(name,data);
}

function setAdminSession(actor) {
  appData.isAdmin = !!actor;
  appData.adminRole = actor?.role || null;
  appData.adminName = actor?.name || "";
  applyAdminPermissions();
}

async function initializeSession() {
  try {
    await auth.setPersistence(firebase.auth.Auth.Persistence.SESSION);
    const user = await new Promise((resolve) => {
      const unsubscribe = auth.onAuthStateChanged((user) => {
        unsubscribe();
        resolve(user);
      });
    });
    if (!user) await auth.signInAnonymously();
    const token = await auth.currentUser.getIdTokenResult();
    if (token.claims.adminRole) {
      try {
        setAdminSession((await callBackend("adminSession")).actor);
      } catch {
        await auth.signOut();
        await auth.signInAnonymously();
        setAdminSession(null);
      }
    }
    await Promise.all([refreshData(true), loadSystemConfig()]);
    if (appData.isAdmin) switchTab("dashboard");
  } catch (e) {
    setAdminSession(null);
    Swal.fire(
      "เชื่อมต่อไม่สำเร็จ",
      "กรุณาตรวจสอบการเปิดใช้ Firebase Authentication และ Backend: " +
        e.message,
      "error",
    );
  }
}

function updateAdminIdentity() {
  setText('account-role', appData.isAdmin ? `${appData.adminName} · ${isSuperAdmin() ? 'Admin ใหญ่' : 'Admin รอง'}` : '');
  setText(
    "adminIdentity",
    appData.isAdmin
      ? `${appData.adminName} · ${isSuperAdmin() ? "Admin ใหญ่" : "Admin รอง"}`
      : "",
  );
  $("adminIdentity").classList.toggle("hidden", !appData.isAdmin);
}

function applyAdminPermissions() {
  document
    .querySelectorAll(".admin-only")
    .forEach((el) => el.classList.toggle("hidden", !appData.isAdmin));
  document
    .querySelectorAll(".super-admin-only")
    .forEach((el) => el.classList.toggle("hidden", !isSuperAdmin()));
  $("btnLogin").classList.toggle("hidden", appData.isAdmin);
  $("btnLogout").classList.toggle("hidden", !appData.isAdmin);
  updateAdminIdentity();
  if (!isSuperAdmin()) {
    for (const id of ["setting-limited-pass", "setting-limited-confirm"])
      if($(id)) $(id).value = "";
    $("requesterPinRows").replaceChildren();
    $("adminLogList").replaceChildren();
  }
}

const AUDIT_FIELDS = {
  status: "สถานะ",
  requesterName: "ชื่อผู้แจ้ง",
  positionDept: "แผนก",
  phoneNumber: "เบอร์โทร",
  equipmentLocation: "ชื่ออุปกรณ์",
  equipId: "รหัสอุปกรณ์",
  problemDetails: "รายละเอียดปัญหา",
  technician: "ช่าง",
  adminRemarks: "บันทึกช่าง",
  additionalNotes: "หมายเหตุเพิ่มเติม",
  urgency: "ความเร่งด่วน",
  cost: "ค่าใช้จ่าย",
  itemsData: "รายการค่าใช้จ่าย / อะไหล่",
  stockUsage: "รายการเบิกสต๊อก",
  imageBefore: "รูปก่อนซ่อม",
  imageAfter: "รูปหลังซ่อม",
  acceptedDate: "เวลารับงาน",
  completedDate: "เวลาซ่อมเสร็จ",
  techDoneDate: "เวลาช่างจบงาน",
  ownerClosedDate: "เวลาผู้แจ้งยืนยัน",
  requestDate: "เวลาแจ้ง",
  jobID: "เลขใบงาน",
  unrepairableReason: "เหตุผลซ่อมไม่ได้",
  unrepairableDetail: "รายละเอียดซ่อมไม่ได้",
  unrepairableDate: "เวลาแจ้งซ่อมไม่ได้",
  unrepairableConfirmedDate: "เวลายืนยันรับทราบ",
  cancelRequest: "คำขอยกเลิก",
  cancelReason: "เหตุผลยกเลิก",
  cancelRefJobId: "ใบงานอ้างอิง",
  cancelledDate: "เวลายกเลิก",
  cancelRequestedDate: "เวลาขอยกเลิก",
  statusBeforeCancel: "สถานะก่อนยกเลิก",
  jobIdConfig: "รูปแบบเลขใบงาน",
  lists: "แผนก / รายชื่อช่าง",
  adminPass: "รหัส Admin ใหญ่",
  limitedAdminPass: "รหัส Admin รอง",
  userPin: "PIN ผู้แจ้ง",
  superAdminName: "ชื่อ Admin ใหญ่",
  limitedAdminName: "ชื่อ Admin รอง",
};
const AUDIT_PRIVATE_FIELDS = new Set([
  "adminPass",
  "limitedAdminPass",
  "userPin",
  "password",
]);

function changesForLog(row) {
  if(row.changes)return row.changes;
  const before=row.before||{},after=row.after||{};
  const result=[...new Set([...Object.keys(before),...Object.keys(after)])]
    .filter(field=>!['lastAdminLogId','lastModifiedBy','lastModifiedAt','lastRequesterProofId'].includes(field))
    .filter(field=>JSON.stringify(before[field]??null)!==JSON.stringify(after[field]??null))
    .map(field=>({field,before:before[field]??null,after:after[field]??null}));
  if(row.pinChanged)result.push({field:'userPin',before:'ปกปิดรหัส',after:'ปกปิดรหัส'});
  return result;
}

async function recordAdminEvent(action, target = "") {
  return callBackend("adminEvent", { action, target });
}

async function auditedJobWrite(jobId, patch, action, mode = "update") {
  return callBackend("adminJobWrite", { jobId, patch, mode, action });
}

function canCompleteJob(job) {
  return (
    ["Waiting", "Processing", "WaitingParts", "PendingApproval"].includes(
      job.status,
    ) && !job.cancelRequest
  );
}

async function completeJob(jobId) {
  if (!requireAdmin()) return;
  const job = appData.reqs.find((r) => r.jobID === jobId);
  if (!job || !canCompleteJob(job))
    return Swal.fire(
      "ทำรายการไม่ได้",
      "งานนี้ไม่อยู่ในสถานะที่กดซ่อมเสร็จได้",
      "warning",
    );
  const confirm = await Swal.fire({
    title: "ยืนยันซ่อมเสร็จ?",
    text: `ใบ ${jobId} จะรอผู้แจ้งยืนยัน PIN เพื่อปิดงาน`,
    icon: "question",
    showCancelButton: true,
    confirmButtonText: "ซ่อมเสร็จ",
    cancelButtonText: "ยกเลิก",
  });
  if (!confirm.isConfirmed) return;
  Swal.fire({
    title: "กำลังบันทึก...",
    allowOutsideClick: false,
    didOpen: () => Swal.showLoading(),
  });
  try {
    await auditedJobWrite(jobId, {}, "กดซ่อมเสร็จ", "complete");
    await syncJobById(jobId);
    await refreshData(true);
    Swal.fire("บันทึกแล้ว", "ซ่อมเสร็จ รอผู้แจ้งยืนยันปิดงาน", "success");
  } catch (e) {
    Swal.fire("บันทึกไม่สำเร็จ", e.message, "error");
  }
}

let adminLogRows = [];
let adminLogCursor = null;
let adminLogLoading = false;

async function loadAdminLogs(reset = true) {
  if (!requireSuperAdmin() || adminLogLoading) return;
  adminLogLoading = true;
  const more = $("adminLogMore");
  more.disabled = true;
  try {
    let query = db
      .collection("adminLogs")
      .orderBy("timestamp", "desc")
      .limit(50);
    if (!reset && adminLogCursor) query = query.startAfter(adminLogCursor);
    const snap = await query.get();
    if (!isSuperAdmin()) return;
    const rows = snap.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
    adminLogRows = reset ? rows : [...adminLogRows, ...rows];
    adminLogCursor = snap.docs[snap.docs.length - 1] || null;
    more.classList.toggle("hidden", snap.docs.length < 50);
    renderAdminLogs();
  } catch (e) {
    if (reset)
      $("adminLogList").textContent =
        "โหลด Log ไม่สำเร็จ กรุณาตรวจสอบสิทธิ์ฐานข้อมูลแล้วลองอีกครั้ง";
    Swal.fire("โหลด Log ไม่สำเร็จ", e.message, "error");
  } finally {
    adminLogLoading = false;
    more.disabled = false;
  }
}

function auditDisplay(value, field) {
  if (value === null || value === undefined || value === "") return "—";
  if (field === "status" || field === "statusBeforeCancel")
    return STATUS_TH[value] || String(value);
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function renderAdminLogs() {
  if (!isSuperAdmin()) return;
  const query = $("adminLogSearch").value.trim().toLocaleLowerCase();
  const rows = adminLogRows.filter((row) =>
    JSON.stringify(row).toLocaleLowerCase().includes(query),
  );
  const list = $("adminLogList");
  list.innerHTML =
    rows
      .map((row) => {
        const date = row.timestamp?.toDate
          ? row.timestamp.toDate()
          : row.timestamp
            ? new Date(row.timestamp)
            : null;
        const time =
          date && !isNaN(date)
            ? date.toLocaleString("th-TH", { timeZone: "Asia/Bangkok" })
            : "รอบันทึกเวลา";
        const actor = row.actor || {};
        const changes = changesForLog(row)
          .map((change) => {
            const privateField = AUDIT_PRIVATE_FIELDS.has(change.field);
            return `<tr><td class="p-2 font-medium">${escHtml(change.label || AUDIT_FIELDS[change.field] || change.field)}</td>
                <td class="p-2 whitespace-pre-wrap break-all">${escHtml(privateField ? "ปกปิดรหัส" : auditDisplay(change.before, change.field))}</td>
                <td class="p-2 whitespace-pre-wrap break-all">${escHtml(privateField ? "ปกปิดรหัส" : auditDisplay(change.after, change.field))}</td></tr>`;
          })
          .join("");
        return `<article class="card p-4"><div class="flex flex-wrap justify-between gap-2"><strong>${escHtml(row.action)} ${escHtml(row.target || "")}</strong><time class="text-xs text-slate-500">${escHtml(time)}</time></div>
            <p class="text-sm text-blue-700 mt-1">${actor.role === "super" ? "Admin ใหญ่" : "Admin รอง"} · ${escHtml(actor.uid || actor.name || '')}</p>
            ${changes ? `<div class="overflow-x-auto mt-3"><table class="w-full text-sm table-fixed"><thead><tr><th class="p-2 text-left w-1/4">ข้อมูล</th><th class="p-2 text-left">ก่อนแก้ไข</th><th class="p-2 text-left">หลังแก้ไข</th></tr></thead><tbody>${changes}</tbody></table></div>` : ""}</article>`;
      })
      .join("") ||
    '<div class="card p-6 text-center text-slate-500">ไม่พบ Log ที่ตรงกับการค้นหา</div>';
}

function renderRequesterPins() {
  if (!isSuperAdmin()) return;
  const query = $("requesterPinSearch").value.trim().toLocaleLowerCase();
  const rows = appData.reqs.filter((job) =>
    [job.jobID, job.requesterName, job.equipmentLocation]
      .join(" ")
      .toLocaleLowerCase()
      .includes(query),
  );
  const tbody = $("requesterPinRows");
  tbody.replaceChildren();
  for (const job of rows) {
    const tr = document.createElement("tr");
    for (const value of [job.jobID, job.requesterName, job.equipmentLocation]) {
      const td = document.createElement("td");
      td.className = "p-3";
      td.textContent = value || "—";
      tr.appendChild(td);
    }
    const td = document.createElement("td");
    td.className = "p-3";
    const button = document.createElement("button");
    button.className = "btn-soft px-3 py-1";
    button.textContent = "ดู PIN";
    button.addEventListener("click", () => revealRequesterPin(job.jobID));
    td.appendChild(button);
    tr.appendChild(td);
    tbody.appendChild(tr);
  }
  if (!rows.length) {
    const tr = tbody.insertRow();
    const td = tr.insertCell();
    td.colSpan = 4;
    td.className = "p-6 text-center";
    td.textContent = "ไม่พบใบงาน";
  }
}

async function revealRequesterPin(jobId) {
  if (!requireSuperAdmin()) return;
  try {
    const result = await callBackend("adminGetPin", { jobId });
    if (!isSuperAdmin()) return;
    await Swal.fire({
      title: "PIN ผู้แจ้ง",
      text: `ใบ ${jobId}: ${result.pin || "ไม่ได้ตั้งรหัส"}`,
      confirmButtonText: "ปิด",
    });
  } catch (e) {
    Swal.fire("เปิดดู PIN ไม่สำเร็จ", e.message, "error");
  }
}

async function changeOwnAdminPassword(event) {
  event.preventDefault();
  if (!requireAdmin()) return;
  const currentPassword = $('account-current-password').value;
  const password = $('account-new-password').value;
  if (password.length < 8 || password.length > 128 || password !== $('account-confirm-password').value) {
    return Swal.fire('ข้อมูลไม่ถูกต้อง', 'รหัสใหม่ต้องมีอย่างน้อย 8 ตัว และกรอกยืนยันให้ตรงกัน', 'warning');
  }
  Swal.fire({title:'กำลังบันทึกรหัสใหม่...',allowOutsideClick:false,didOpen:()=>Swal.showLoading()});
  try {
    await callBackend('maintenanceAdminUpdate', {role:appData.adminRole,currentPassword,password});
    ['account-current-password','account-new-password','account-confirm-password'].forEach(id=>$(id).value='');
    await Swal.fire('เปลี่ยนรหัสแล้ว','กรุณาเข้าสู่ระบบอีกครั้งด้วยรหัสใหม่','success');
    await logout();
  } catch (error) { Swal.fire('เปลี่ยนรหัสไม่สำเร็จ',error.message,'error'); }
}

async function refreshAdminAccountStatus() {
  if(!requireSuperAdmin())return;
  const button=$('limited-account-save');button.disabled=true;
  appData.adminAccountStatusLoaded=false;
  try {
    const result=await callBackend('maintenanceAdminSession',{includeAccounts:true});
    const limited=result.accounts?.find(account=>account.role==='limited');
    if(!limited)throw new Error('ยังตรวจสถานะบัญชีไม่ได้');
    appData.limitedEnabled=limited.enabled;
    $('setting-limited-enabled').checked=limited.enabled;
    $('limited-account-status').textContent=limited.enabled?'บัญชี Admin รองเปิดใช้งานอยู่':'บัญชี Admin รองปิดใช้งานอยู่';
    appData.adminAccountStatusLoaded=true;button.disabled=false;
  } catch(error) { $('limited-account-status').textContent=error.message; }
}

async function saveLimitedAdminAccount() {
  if(!requireSuperAdmin()||!appData.adminAccountStatusLoaded)return;
  const password=$('setting-limited-pass').value;
  const enabled=$('setting-limited-enabled').checked;
  if(password&&(password.length<8||password.length>128||password!==$('setting-limited-confirm').value))return Swal.fire('ข้อมูลไม่ถูกต้อง','รหัสใหม่ต้องมีอย่างน้อย 8 ตัว และยืนยันให้ตรงกัน','warning');
  if(enabled&&!appData.limitedEnabled&&!password)return Swal.fire('กรุณาตั้งรหัสใหม่','การเปิดบัญชีอีกครั้งต้องตั้งรหัสใหม่ให้ Admin รอง','warning');
  const input={role:'limited'};
  if(password)input.password=password;
  if(enabled!==appData.limitedEnabled)input.disabled=!enabled;
  if(Object.keys(input).length===1)return Swal.fire('ยังไม่มีการเปลี่ยนแปลง','','info');
  try {
    await callBackend('maintenanceAdminUpdate',input);
    $('setting-limited-pass').value='';$('setting-limited-confirm').value='';
    await refreshAdminAccountStatus();Swal.fire('บันทึกแล้ว','บันทึกบัญชีและ Log แล้ว','success');
  } catch(error) { Swal.fire('บันทึกไม่สำเร็จ',error.message,'error'); }
}

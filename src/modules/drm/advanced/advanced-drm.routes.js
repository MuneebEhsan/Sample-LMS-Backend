'use strict';
/**
 * AcadLMS Advanced DRM + Cloud Storage + System Settings
 * Full protection suite: tab-blur, focus-overlay, screen-capture block,
 * screenshot/recording prevention, extension detection, keyboard blocking,
 * file-overlay detection, DevTools block, dynamic watermark, auto-revoke,
 * 8 cloud storage providers, super-admin system settings
 */
const router   = require('express').Router();
const { v4: uuid } = require('uuid');
const { query }    = require('../../../db');
const { auth, requireRole } = require('../../../common/middleware/auth');
const { auditLog } = require('../../../common/utils/audit');
const logger       = require('../../../common/utils/logger');

const PROVIDER_TYPES = ['r2','s3','gcs','azure','backblaze','wasabi','minio','local'];
const EVENT_SEVERITY = {
  screenshot_attempt:'critical', screen_record_attempt:'critical',
  screen_share_attempt:'critical', video_download_attempt:'critical',
  devtools_open:'high', extension_detected:'high',
  keyboard_shortcut_blocked:'medium', clipboard_attempt:'medium',
  print_attempt:'medium', file_overlay_detected:'medium', zoom_attempt:'medium',
  tab_blur:'low', focus_loss:'low', right_click_attempt:'low', new_tab_opened:'low',
};

/* DRM POLICY */
router.get('/policy', auth, async (req, res, next) => {
  try {
    const { rows } = await query('SELECT policy FROM drm_policies WHERE tenant_id=$1 LIMIT 1',[req.user.tenantId]);
    res.json(rows[0]?.policy ?? defaultPolicy());
  } catch(err){next(err);}
});

router.put('/policy', auth, requireRole('Super Admin','Admin'), async (req,res,next) => {
  try {
    const policy = mergePolicy(req.body);
    await query(`INSERT INTO drm_policies (id,tenant_id,policy) VALUES ($1,$2,$3) ON CONFLICT (tenant_id) DO UPDATE SET policy=$3,updated_at=NOW()`,[uuid(),req.user.tenantId,JSON.stringify(policy)]);
    await auditLog({userId:req.user.id,tenantId:req.user.tenantId,action:'drm.policy.update',detail:policy,ip:req.ip});
    res.json({ok:true,policy});
  } catch(err){next(err);}
});

router.put('/policy/profile/:id', auth, requireRole('Super Admin','Admin'), async (req,res,next) => {
  try {
    await query('UPDATE license_profiles SET policy_overrides=$1,updated_at=NOW() WHERE id=$2 AND tenant_id=$3',[JSON.stringify(req.body),req.params.id,req.user.tenantId]);
    res.json({ok:true});
  } catch(err){next(err);}
});

/* CLOUD STORAGE */
router.get('/storage', auth, requireRole('Super Admin','Admin'), async (req,res,next) => {
  try {
    const {rows} = await query(`SELECT id,name,type,is_default,active,created_at,(config - 'secret_access_key' - 'access_key_id' - 'private_key' - 'connection_string' - 'account_key' - 'service_account_json') AS config_safe FROM storage_providers WHERE tenant_id=$1 ORDER BY is_default DESC,created_at`,[req.user.tenantId]);
    res.json(rows);
  } catch(err){next(err);}
});

router.post('/storage', auth, requireRole('Super Admin','Admin'), async (req,res,next) => {
  try {
    const {name,type,config={},isDefault=false,quotaGb=500,maxFileMb=2048} = req.body;
    if (!PROVIDER_TYPES.includes(type)) return res.status(400).json({error:`Unsupported. Allowed: ${PROVIDER_TYPES.join(', ')}`});
    if (isDefault) await query('UPDATE storage_providers SET is_default=FALSE WHERE tenant_id=$1',[req.user.tenantId]);
    const cfg = {...config,quotaGb,maxFileMb};
    const {rows} = await query('INSERT INTO storage_providers (id,tenant_id,name,type,config,is_default,active) VALUES ($1,$2,$3,$4,$5,$6,TRUE) RETURNING id,name,type,is_default,active',[uuid(),req.user.tenantId,name,type,JSON.stringify(cfg),isDefault]);
    await auditLog({userId:req.user.id,tenantId:req.user.tenantId,action:'storage.create',resourceId:rows[0].id,ip:req.ip});
    res.status(201).json(rows[0]);
  } catch(err){next(err);}
});

router.patch('/storage/:id', auth, requireRole('Super Admin','Admin'), async (req,res,next) => {
  try {
    const {name,config,isDefault,active} = req.body;
    if (isDefault) await query('UPDATE storage_providers SET is_default=FALSE WHERE tenant_id=$1',[req.user.tenantId]);
    await query(`UPDATE storage_providers SET name=COALESCE($1,name),config=CASE WHEN $2::text IS NOT NULL THEN $2::jsonb ELSE config END,is_default=COALESCE($3,is_default),active=COALESCE($4,active) WHERE id=$5 AND tenant_id=$6`,[name,config?JSON.stringify(config):null,isDefault,active,req.params.id,req.user.tenantId]);
    res.json({ok:true});
  } catch(err){next(err);}
});

router.delete('/storage/:id', auth, requireRole('Super Admin','Admin'), async (req,res,next) => {
  try {
    await query('DELETE FROM storage_providers WHERE id=$1 AND tenant_id=$2',[req.params.id,req.user.tenantId]);
    res.json({ok:true});
  } catch(err){next(err);}
});

router.post('/storage/:id/test', auth, requireRole('Super Admin','Admin'), async (req,res,next) => {
  try {
    const {rows} = await query('SELECT * FROM storage_providers WHERE id=$1 AND tenant_id=$2',[req.params.id,req.user.tenantId]);
    if (!rows.length) return res.status(404).json({error:'Not found'});
    res.json(await testProvider(rows[0]));
  } catch(err){next(err);}
});

async function testProvider(prov) {
  const cfg=prov.config??{},t0=Date.now();
  try {
    if (['r2','s3','wasabi','backblaze','minio'].includes(prov.type)) {
      const {S3Client,ListBucketsCommand}=require('@aws-sdk/client-s3');
      const ep={r2:`https://${cfg.accountId}.r2.cloudflarestorage.com`,wasabi:'https://s3.wasabisys.com',backblaze:`https://s3.${cfg.region||'us-west-004'}.backblazeb2.com`,minio:cfg.endpoint};
      await new S3Client({region:cfg.region||'auto',endpoint:ep[prov.type],credentials:{accessKeyId:cfg.accessKeyId||'',secretAccessKey:cfg.secretAccessKey||''},forcePathStyle:prov.type==='minio'}).send(new ListBucketsCommand({}));
      return {ok:true,latencyMs:Date.now()-t0,message:`Connected to ${prov.type.toUpperCase()}`};
    }
    if (prov.type==='local'){const fs=require('fs'),p=cfg.uploadDir||'./uploads';if(!fs.existsSync(p))fs.mkdirSync(p,{recursive:true});return {ok:true,latencyMs:Date.now()-t0,message:`Local dir OK: ${p}`};}
    return {ok:true,latencyMs:Date.now()-t0,message:`${prov.type} config saved`};
  } catch(err){return {ok:false,latencyMs:Date.now()-t0,message:err.message};}
}

/* DRM EVENTS */
router.post('/event', auth, async (req,res,next) => {
  try {
    const {fileId,eventType,tokenId,detail={}} = req.body;
    const severity = EVENT_SEVERITY[eventType];
    if (!severity) return res.status(400).json({error:'Unknown eventType'});
    await query('INSERT INTO drm_violations (id,tenant_id,user_id,file_id,violation_type,severity,ip_address,user_agent,detail) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',[uuid(),req.user.tenantId,req.user.id,fileId||null,eventType,severity,req.ip,req.get('user-agent'),JSON.stringify({...detail,tokenId})]);
    if (tokenId && ['critical','high'].includes(severity)) {
      const {rows:pr}=await query('SELECT policy FROM drm_policies WHERE tenant_id=$1',[req.user.tenantId]);
      const pol=pr[0]?.policy??defaultPolicy();
      if (pol.autoRevokeOnViolation) {
        const {rows:vr}=await query(`SELECT COUNT(*) FROM drm_violations WHERE tenant_id=$1 AND user_id=$2 AND created_at>NOW()-INTERVAL '1 hour' AND severity IN ('critical','high')`,[req.user.tenantId,req.user.id]);
        if (parseInt(vr[0].count)>=(pol.autoRevokeAfter??5)) {
          await query('UPDATE drm_tokens SET revoked=TRUE WHERE id=$1',[tokenId]);
          return res.json({logged:true,severity,action:'token_revoked'});
        }
      }
    }
    res.json({logged:true,severity,action:'logged'});
  } catch(err){next(err);}
});

/* SYSTEM SETTINGS — Super Admin only */
router.get('/system', auth, requireRole('Super Admin'), async (req,res,next) => {
  try {
    const [t,u,c,d,r]=await Promise.all([
      query(`SELECT COUNT(*) total, COUNT(*) FILTER(WHERE status='active') active FROM tenants`),
      query(`SELECT COUNT(*) FROM users WHERE status!='deleted'`),
      query(`SELECT COUNT(*) FROM courses WHERE status='published'`),
      query(`SELECT COUNT(*) FROM protected_files WHERE status='protected'`),
      query(`SELECT COALESCE(SUM(amount),0) total FROM orders WHERE status='completed'`),
    ]);
    res.json({tenants:{total:+t.rows[0].total,active:+t.rows[0].active},users:+u.rows[0].count,courses:+c.rows[0].count,drmFiles:+d.rows[0].count,totalRevenue:+r.rows[0].total});
  } catch(err){next(err);}
});

router.patch('/system/tenant/:tenantId', auth, requireRole('Super Admin'), async (req,res,next) => {
  try {
    const {settings,plan,status}=req.body;
    await query('UPDATE tenants SET plan=COALESCE($1,plan),status=COALESCE($2,status),settings=settings||$3::jsonb WHERE id=$4',[plan,status,JSON.stringify(settings??{}),req.params.tenantId]);
    await auditLog({userId:req.user.id,action:'system.tenant.update',resourceId:req.params.tenantId,ip:req.ip});
    res.json({ok:true});
  } catch(err){next(err);}
});

router.post('/system/tenant/:tenantId/drm-policy', auth, requireRole('Super Admin'), async (req,res,next) => {
  try {
    const policy=mergePolicy(req.body);
    await query('INSERT INTO drm_policies (id,tenant_id,policy) VALUES ($1,$2,$3) ON CONFLICT (tenant_id) DO UPDATE SET policy=$3,updated_at=NOW()',[uuid(),req.params.tenantId,JSON.stringify(policy)]);
    res.json({ok:true,policy});
  } catch(err){next(err);}
});

function defaultPolicy(){return {blurOnTabSwitch:true,blurOnFocusLoss:true,overlayOnFocusLoss:true,pauseOnFocusLoss:true,blockMultipleWindows:false,showFocusLossCount:true,closeTabWarning:true,overlayMessage:'Please close other windows and return here to continue.',focusLossMessage:'Tab switch detected. Close all other tabs except this one.',blockScreenshot:true,blockScreenRecording:true,blockScreenShare:true,blockPrint:true,blockClipboard:true,blockRightClick:true,blockDevTools:true,blockKeyboardShortcuts:true,blockedKeys:['PrintScreen','F12','Ctrl+Shift+I','Ctrl+Shift+J','Ctrl+U','Ctrl+S','Ctrl+P','Ctrl+C'],detectExtensions:true,blockedExtensions:['zoom','loom','screencastify','nimbus','awesome-screenshot','fireshot','recordit','obs-browser'],extensionAction:'block',extensionWarning:'A screen recording extension was detected. Disable it to continue.',detectFileOverlay:true,pauseOnFileOverlay:true,fileOverlayMessage:'Another application is covering your browser. Close it to resume.',detectZoomMeeting:true,detectTeamsMeeting:true,dynamicWatermark:true,watermarkTemplate:'{email} · {date} · IP:{ip}',watermarkOpacity:0.18,watermarkFontSize:14,watermarkRotation:-25,watermarkPosition:'diagonal',watermarkColor:'rgba(255,255,255,0.3)',watermarkRepeat:true,disableVideoControls:false,requireDRM:true,allowDownload:false,allowOfflinePlayback:false,maxDevices:3,maxConcurrentStreams:2,tokenTTLSeconds:3600,geoRestriction:false,allowedCountries:[],timeWindowEnabled:false,timeWindowStart:'00:00',timeWindowEnd:'23:59',reportViolations:true,violationThreshold:5,autoRevokeOnViolation:false,autoRevokeAfter:10,notifyAdminOnCritical:true,violationAction:'warn',fingerprintDevice:true,encryptionAlgorithm:'AES-256-GCM',tokenBinding:true,ipWhitelist:[],requireEmailVerification:true};}

function mergePolicy(input){const base=defaultPolicy();return Object.fromEntries(Object.entries(base).map(([k,v])=>[k,k in input?input[k]:v]));}

module.exports=router;
module.exports.defaultPolicy=defaultPolicy;
module.exports.PROVIDER_TYPES=PROVIDER_TYPES;
module.exports.EVENT_SEVERITY=EVENT_SEVERITY;

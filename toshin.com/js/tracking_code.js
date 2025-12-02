/* 多重読み込み回避 */
var trackingLoaded;

if (typeof trackingLoaded == 'undefined') {
trackingLoaded = 1;
} else {
trackingLoaded = 0;
}

if (trackingLoaded == 1) {
function _gaqcheck() {
var flag = 1;
if (typeof _gaq === 'undefined' || flag == 1) {
_gaq = new Object();

_gaq.push = function (obj) {
if (obj[0] == '_setCustomVar') {
a = obj[2];
b = obj[3];

var arr = {};
arr[a] = b;
arr['event'] = 'custom';

dataLayer.push(arr);
//					console.log( "setvariables" );
} else {
if (typeof obj[3] === 'undefined') {
obj[3] = obj[2];
obj[2] = obj[1];
}
dataLayer.push({
event: 'gaqPush',
eventCategory: obj[1],
eventAction: obj[2],
eventLavel: obj[3],
});
//					console.log( "sendevent" );
}
};
} else {
//			console.log( "error" );
}
}

if (window.addEventListener) {
window.addEventListener('load', _gaqcheck(), false);
} else if (window.attachEvent) {
window.attachEvent('onload', _gaqcheck());
} else {
window.onload = _gaqcheck();
}

var gBasePATH = 'www.toshin.com';
var gPathName = document.URL;
var gPathName2 = document.location.pathname;
var gaRename = 0;
var gPattern = '';
var gDuplicate = 0;
var customCal = 0;
var gZaitaku = 0;
var gIkuei = 0;

/* ------------------------------------------------------------------
Tagmanager設定
------------------------------------------------------------------- */
var GTM_id = 'GTM-G26Z';

/* ------------------------------------------------------------------
Yahoo!共通変数 
------------------------------------------------------------------- */
var yahoo_conversion_id = '1000067720';
var yahoo_conversion_value = 0;
var customCal = 0;

/* ------------------------------------------------------------------
Yahoo!共通変数 
------------------------------------------------------------------- */
if (
gPathName.indexOf('service.toshin.com/guest/regist_user') != -1 ||
gPathName.indexOf(gBasePATH + '/service/regist.html') != -1 ||
gPathName.indexOf(gBasePATH + '/service/regist2.html') != -1 ||
gPathName.indexOf(gBasePATH + '/service/regist3.html') != -1 ||
gPathName.indexOf(gBasePATH + '/entry/jhsTokubetsuShotai/complete') != -1
) {
gDuplicate = 1;

// 入学申し込み(hs)
if (eventName == 'nyugaku_hs') {
// 入学申し込み(衛星)
} else if (eventName == 'nyugaku_es') {
// 資料請求(hs)
} else if (eventName == 'shiryo_hs' || eventName == 'taiken_hs') {
// 資料請求(衛星)
} else if (eventName == 'shiryo_es' || eventName == 'taiken_es') {
// 在宅受講コース 資料請求
} else if (eventName == 'siryou_vod' || eventName == 'siryou_vodkoza') {
gZaitaku = 1;
// 特別招待講習(hs)　申込み
} else if (eventName == 'event_shotai_hs') {
// 特別招待講習(衛星)　申込み
} else if (eventName == 'event_shotai_es') {
// 特別招待講習(hs) 招待状請求20160701追加
} else if (eventName == 'event_shotai_seikyu_hs') {
// 特別招待講習(衛星) 招待状請求20160701追加
} else if (eventName == 'event_shotai_seikyu_es') {
// 自宅オンライン講習(hs)
} else if (eventName == 'event_shotai_study_home_hs') {
// 自宅オンライン講習(衛星)
} else if (eventName == 'event_shotai_study_home_es') {
// 特別招待講習(hs)　申込み 中学
} else if (eventName == 'jhs_shotai_hs') {
// 特別招待講習(衛星)　申込み 中学NET
} else if (eventName == 'jhs_shotai_es') {
// 先取り講習(hs)　申込み 中学
} else if (eventName == 'jhs_sakidori_hs') {
// 先取り講習(衛星)　申込み 中学NET
} else if (eventName == 'jhs_sakidori_es') {
// 部活生特別(hs)
} else if (
eventName == 'event_bukatsu_shotai_hs' ||
eventName == 'event_bukatsu_shotai_seikyu_hs'
) {
// 部活生特別(衛星)
} else if (
eventName == 'event_bukatsu_shotai_es' ||
eventName == 'event_bukatsu_shotai_seikyu_es'
) {
// 先取り特訓講習(hs)
} else if (
eventName == 'event_sakidori_hs' ||
eventName == 'event_shotai_h1_hs' ||
eventName == 'event_shotaientry_h1_hs'
) {
// 先取り特訓講習(衛星)
} else if (
eventName == 'event_sakidori_es' ||
eventName == 'event_shotai_h1_es' ||
eventName == 'event_shotaientry_h1_es'
) {
// 季節講習(hs)
} else if (eventName == 'summer_hs' || eventName == 'winter_hs') {
// 季節講習(衛星)
} else if (eventName == 'summer_es' || eventName == 'winter_es') {
// 特別公開授業
} else if (eventName == 'event_kokai') {
// 個別面談(hs)
} else if (eventName == 'event_koex_hs') {
// 個別面談(衛星)
} else if (eventName == 'event_koex_es') {
// 高０生数学特待生(hs、衛星)
} else if (
eventName == 'sugaku_tokutai_hs' ||
eventName == 'sugaku_tokutai_es'
) {
// EnglishCamp
} else if (
eventName == 'event_english_camp_hs' ||
eventName == 'event_english_camp_es'
) {
// 定期テスト対策特別招待校講習(hs/衛星)
} else if (
eventName == 'event_shotai_routine_test_hs' ||
eventName == 'event_shotai_routine_test_es'
) {
// 模試
} else if (eventName.indexOf('moshi') != -1) {
gDuplicate = 0;
} else {
gDuplicate = 0;
}

// =============================================================================================
//  GoogleAnalyticsPageName 2012-0518
// =============================================================================================
gaRename = 1;

switch (eventName) {
case 'nyugaku_hs':
gaPageName = '/hs/cv/nyugaku_complete.html';
break;
case 'nyugaku_es':
gaPageName = '/es/cv/nyugaku_complete.html';
break;
case 'shiryo_hs':
gaPageName = '/hs/cv/shiryou_complete.html';
break;
case 'shiryo_es':
gaPageName = '/es/cv/shiryou_complete.html';
break;
case 'siryou_vod':
gaPageName = '/hs/vod/shiryou_complete.html';
break;
case 'siryou_vodkoza':
gaPageName = '/hs/vod/shiryou_complete.html';
break;
case 'event_shotai_hs':
gaPageName = '/hs/cv/shoutai_complete.html';
break;
case 'event_shotai_es':
gaPageName = '/es/cv/shoutai_complete.html';
break;
case 'jhs_shotai_hs':
gaPageName = '/hs/cv/jhs_shoutai_complete.html';
break;
case 'jhs_shotai_es':
gaPageName = '/es/cv/jhs_shoutai_complete.html';
break;
case 'jhs_sakidori_hs':
gaPageName = '/hs/cv/jhs_sakidori_complete.html';
break;
case 'jhs_sakidori_es':
gaPageName = '/es/cv/jhs_sakidori_complete.html';
break;

// 医学部特進
case 'igakubu_shiryo_hs':
gaPageName = '/hs/cv/igakubu_shiryo_hs_complete.html';
break;
case 'igakubu_shiryo_es':
gaPageName = '/es/cv/igakubu_shiryo_es_complete.html';
break;

//20160701追加
case 'event_shotai_seikyu_hs':
gaPageName = '/hs/cv/shoutai_seikyu_complete.html';
break;
//20160701追加
case 'event_shotai_seikyu_es':
gaPageName = '/es/cv/shoutai_seikyu_complete.html';
break;
case 'event_kokai':
gaPageName = '/hs/event/koukai_complete.html';
break;
case 'event_koex_hs':
gaPageName = '/hs/cv/kobetsu_complete.html';
break;
case 'event_koex_es':
gaPageName = '/es/cv/kobetsu_complete.html';
break;

// 体験授業 20150107
case 'taiken_hs':
gaPageName = '/hs/cv/taiken_complete.html';
break;
case 'taiken_es':
gaPageName = '/es/cv/taiken_complete.html';
break;

// 先取り特訓講習
case 'event_sakidori_hs':
gaPageName = '/hs/cv/sakidori_complete.html';
break;
case 'sakidori_shotai_hs':
gaPageName = '/hs/cv/sakidori_complete.html';
break;
case 'event_shotai_h1_hs':
gaPageName = '/hs/cv/sakidori_complete.html';
break;
case 'event_shotaientry_h1_hs':
gaPageName = '/hs/cv/sakidori_complete.html';
break;
case 'event_sakidori_es':
gaPageName = '/es/cv/sakidori_complete.html';
break;
case 'sakidori_shotai_es':
gaPageName = '/hs/cv/sakidori_complete.html';
break;
case 'event_shotai_h1_es':
gaPageName = '/es/cv/sakidori_complete.html';
break;
case 'event_shotaientry_h1_es':
gaPageName = '/es/cv/sakidori_complete.html';
break;
case 'event_shotai_seikyu_h1_hs':
gaPageName = '/hs/cv/sakidori_seikyu_complete.html';
break;
case 'event_shotai_seikyu_h1_es':
gaPageName = '/es/cv/sakidori_seikyu_complete.html';
break;

// 部活生特別
case 'event_bukatsu_hs':
gaPageName = '/hs/cv/bukatsu_complete.html';
break;
case 'event_bukatsu_es':
gaPageName = '/es/cv/bukatsu_complete.html';
break;
case 'event_bukatsu_shotai_hs':
gaPageName = '/hs/cv/bukatsu_complete.html';
break;
case 'event_bukatsu_shotai_es':
gaPageName = '/es/cv/bukatsu_complete.html';
break;
case 'event_bukatsu_shotai_seikyu_hs':
gaPageName = '/hs/cv/bukatsu_complete.html';
break;
case 'event_bukatsu_shotai_seikyu_es':
gaPageName = '/es/cv/bukatsu_complete.html';
break;

// 部活生特別
case 'event_bukatsu_hs':
gaPageName = '/hs/cv/bukatsu_complete.html';
break;
case 'event_bukatsu_es':
gaPageName = '/es/cv/bukatsu_complete.html';
break;
case 'event_bukatsu_shotai_hs':
gaPageName = '/hs/cv/bukatsu_complete.html';
break;
case 'event_bukatsu_shotai_es':
gaPageName = '/es/cv/bukatsu_complete.html';
break;
case 'event_bukatsu_shotai_seikyu_hs':
gaPageName = '/hs/cv/bukatsu_complete.html';
break;
case 'event_bukatsu_shotai_seikyu_es':
gaPageName = '/es/cv/bukatsu_complete.html';
break;

// 4技能特別招招待講習
case 'event_4ginou_shotai_hs':
gaPageName = '/hs/cv/4ginou_shotai_complete.html';
break;
case 'event_4ginou_shotai_es':
gaPageName = '/es/cv/4ginou_shotai_complete.html';
break;
case 'event_4ginou_shotai_seikyu_hs':
gaPageName = '/hs/cv/4ginou_shotai_seikyu_complete.html';
break;
case 'event_4ginou_shotai_seikyu_es':
gaPageName = '/es/cv/4ginou_shotai_seikyu_complete.html';
break;

// 自宅オンライン講習
case 'event_shotai_study_home_hs':
gaPageName = '/hs/cv/shotai_study_home.html';
break;
case 'event_shotai_study_home_es':
gaPageName = '/es/cv/shotai_study_home.html';
break;

// 全国統一高校生テスト事後面談
case 'toitsutest_mendan_hs':
gaPageName = '/hs/cv/toitsutest_mendan_complete.html';
break;
case 'toitsutest_mendan_es':
gaPageName = '/es/cv/toitsutest_mendan_complete.html';
break;

// センター試験本番レベル模試事後面談
case 'advice_mendan_hs':
gaPageName = '/hs/cv/advice_mendan_complete.html';
break;
case 'advice_mendan_es':
gaPageName = '/es/cv/advice_mendan_complete.html';
break;

// 季節講習
case 'summer_hs':
gaPageName = '/hs/cv/kisetsu_complete.html';
break;
case 'summer_es':
gaPageName = '/es/cv/kisetsu_complete.html';
break;

// 季節講習
case 'summer_hs':
gaPageName = '/hs/cv/kisetsu_complete.html';
break;
case 'summer_es':
gaPageName = '/es/cv/kisetsu_complete.html';
break;

// 高０生数学特待(hs、衛星)
case 'sugaku_tokutai_hs':
gaPageName = '/hs/cv/sugaku_tokutai_complete.html';
break;
case 'sugaku_tokutai_es':
gaPageName = '/es/cv/sugaku_tokutai_complete.html';
break;
case 'sugaku_tokutai_superelite_hs':
gaPageName = '/hs/cv/sugaku_tokutai_superelite_hs_complete.html';
break;
case 'sugaku_tokutai_superelite_es':
gaPageName = '/es/cv/sugaku_tokutai_superelite_es_complete.html';
break;

// GlobalEnglishCamp(hs、衛星)
case 'event_english_camp_hs':
gaPageName = '/hs/cv/english_camp_complete.html';
break;
case 'event_english_camp_es':
gaPageName = '/es/cv/english_camp_complete.html';
break;

// 定期テスト対策特別招待校講習(hs/衛星)
case 'event_shotai_routine_test_hs':
gaPageName = '/hs/cv/shotai_routine_test_complete.html';
break;
case 'event_shotai_routine_test_es':
gaPageName = '/es/cv/shotai_routine_test_complete.html';
break;

// 教育セミナー(hs、衛星)
case 'seminar_hs':
gaPageName = '/hs/cv/seminar_complete.html';
break;
case 'seminar_es':
gaPageName = '/es/cv/seminar_complete.html';
break;

// センター試験同日体験受験
case 'moshi_dojitsu_hs':
gaPageName = '/hs/moshi/dojitsu_complete.html';
break;
case 'moshi_dojitsu_es':
gaPageName = '/es/moshi/dojitsu_complete.html';
break;

// センター試験本番レベル模試
case 'moshi_center_hs':
gaPageName = '/hs/moshi/center_complete.html';
break;
case 'moshi_center_es':
gaPageName = '/es/moshi/center_complete.html';
break;

// ------------------------------------------------------------------------------------------
// 旧七帝大本番レベル模試
// ------------------------------------------------------------------------------------------
// 京大本番レベル模試
case 'moshi_kyodai_hs':
gaPageName = '/hs/moshi/nana_kyodai_complete.html';
break;
case 'moshi_kyodai_es':
gaPageName = '/es/moshi/nana_kyodai_complete.html';
break;

// 東大本番レベル模試
case 'moshi_todai_hs':
gaPageName = '/hs/moshi/nana_todai_complete.html';
break;
case 'moshi_todai_es':
gaPageName = '/es/moshi/nana_todai_complete.html';
break;

// 名大本番レベル模試
case 'moshi_meidai_hs':
gaPageName = '/hs/moshi/nana_meidai_complete.html';
break;
case 'moshi_meidai_es':
gaPageName = '/es/moshi/nana_meidai_complete.html';
break;

// 阪大本番レベル模試
case 'moshi_handai_hs':
gaPageName = '/hs/moshi/nana_handai_complete.html';
break;
case 'moshi_handai_es':
gaPageName = '/es/moshi/nana_handai_complete.html';
break;

// 北大本番レベル模試
case 'moshi_hokudai_hs':
gaPageName = '/hs/moshi/nana_hokudai_complete.html';
break;
case 'moshi_hokudai_es':
gaPageName = '/es/moshi/nana_hokudai_complete.html';
break;

// 九大本番レベル模試
case 'moshi_kyudai_hs':
gaPageName = '/hs/moshi/nana_kyudai_complete.html';
break;
case 'moshi_kyudai_es':
gaPageName = '/es/moshi/nana_kyudai_complete.html';
break;

// 東北大本番レベル模試
case 'moshi_tohokudai_hs':
gaPageName = '/hs/moshi/nana_tohokudai_complete.html';
break;
case 'moshi_tohokudai_es':
gaPageName = '/es/moshi/nana_tohokudai_complete.html';
break;

// ------------------------------------------------------------------------------------------
// その他模試
// ------------------------------------------------------------------------------------------
// 東大入試同日体験受験
case 'moshi_todai_hs':
gaPageName = '/hs/moshi/other_todai_complete.html';
break;
case 'moshi_todai_es':
gaPageName = '/es/moshi/other_todai_complete.html';
break;

// 難関大本番レベル記述模試
case 'moshi_nankan_hs':
gaPageName = '/hs/moshi/other_nankan_complete.html';
break;
case 'moshi_nankan_es':
gaPageName = '/es/moshi/other_nankan_complete.html';
break;

// 有名大本番レベル記述模試
case 'moshi_yumei_hs':
gaPageName = '/hs/moshi/other_yumei_complete.html';
break;
case 'moshi_yumei_es':
gaPageName = '/es/moshi/other_yumei_complete.html';
break;

// センター試験高校生レベル模試
case 'moshi_high_hs':
gaPageName = '/hs/moshi/other_high_complete.html';
break;
case 'moshi_high_es':
gaPageName = '/es/moshi/other_high_complete.html';
break;

// 大学合格基礎力判定テスト
case 'moshi_basic_hs':
gaPageName = '/hs/moshi/other_basic_complete.html';
break;
case 'moshi_basic_es':
gaPageName = '/es/moshi/other_basic_complete.html';
break;

// 全国統一高校生テスト
case 'toitsu_test':
gaPageName = '/toitsutest/moushikomi/confirm.php';
break;

// 全国統一医学部テスト
case 'moshi_igakubu_hs':
gaPageName = '/hs/moshi/other_igakubu_complete.html';
break;
case 'moshi_igakubu_es':
gaPageName = '/es/moshi/other_igakubu_complete.html';
break;
case 'moshi_igakubu_ss':
gaPageName = '/ss/moshi/other_igakubu_complete.html';
break;
case 'igakubu_moshi_hs':
gaPageName = '/hs/moshi/other_igakubu_complete.html';
break;
case 'igakubu_moshi_es':
gaPageName = '/es/moshi/other_igakubu_complete.html';
break;
case 'igakubu_moshi_ss':
gaPageName = '/ss/moshi/other_igakubu_complete.html';
break;

// 共通テスト本番レベル模試
case 'moshi_kyotsu_hs':
gaPageName = '/hs/moshi/other_kyotsu_complete.html';
break;
case 'moshi_kyotsu_es':
gaPageName = '/es/moshi/other_kyotsu_complete.html';
break;

default:
// 模試
if (eventName.indexOf('moshi') != -1 && eventName.indexOf('hs') != -1) {
gaPageName = '/hs/moshi/other_fumei_complete.html';
} else if (
eventName.indexOf('moshi') != -1 &&
eventName.indexOf('es') != -1
) {
gaPageName = '/es/moshi/other_complete.html';
} else {
gaPageName = '/other/' + eventName + '/complete.html';
}
}

if (
gPathName.indexOf('service.toshin.com/guest/regist_user') != -1 &&
typeof webID != 'undefined'
) {
gaPageName = gaPageName + '?guid=' + webID;
}

// カスタム変数
customCal = 1;
}

// 東進ハイスクール中等部、東進中学NET
if (gPathName.indexOf(gBasePATH + '/jhs/form/confirm.php') != -1) {
gDuplicate = 1;
// クオルバ
} else if (
gPathName.indexOf(gBasePATH + '/qualva/thanks/taiken.php?P=form_hs') != -1
) {
gDuplicate = 1;
gaPageName = '/hs/cv/taiken_complete.html';
} else if (
gPathName.indexOf(gBasePATH + '/qualva/thanks/taiken.php?P=form_es') != -1
) {
gDuplicate = 1;
gaPageName = '/es/cv/taiken_complete.html';

// 全国統一高校生テスト
} else if (
gPathName.indexOf(gBasePATH + '/toitsutest/moushikomi/confirm.php') != -1 ||
gPathName.indexOf(gBasePATH + '/toitsutest/moushikomi_smart/confirm.php') !=
-1
) {
// 全国統一高校生テスト申込フォーム
} else if (
gPathName.indexOf(gBasePATH + '/toitsutest/moushikomi/form.php') != -1 ||
gPathName.indexOf(gBasePATH + '/toitsutest/moushikomi_smart/form.php') != -1
) {
document.write(
'<script language="JavaScript" type="text/javascript" src="/js/tracking_toitsutest.js" charset="UTF-8"></script>'
);
}

// =============================================================================================
//  成果地点以外ページ
// =============================================================================================
if (gDuplicate == 0 && document.domain == 'www.toshin.com') {
//   Gakunen RM Tag 2013-0325
// カスタム変数対象URL
if (
gPathName.indexOf(gBasePATH + '/grade_h1/') != -1 ||
gPathName.indexOf(gBasePATH + '/sp/grade_h1/') != -1 ||
gPathName.indexOf(gBasePATH + '/grade_h2/') != -1 ||
gPathName.indexOf(gBasePATH + '/sp/grade_h2/') != -1 ||
gPathName.indexOf(gBasePATH + '/grade_h3/') != -1 ||
gPathName.indexOf(gBasePATH + '/sp/grade_h3/') != -1 ||
gPathName.indexOf('/chugaku/') != -1 ||
gPathName.indexOf('/honka/') != -1 ||
gPathName.indexOf('/bs/univ_english/') != -1 ||
gPathName.indexOf('service.toshin.com/guest/highschool_zt/form.html') !=
-1
) {
customCal = 1;
}

// 新年度入学説明会参加お申し込みフォーム
if (
gPathName.indexOf(gBasePATH + '/event/2013_02_nyugaku/pc/sumit.php') != -1
) {
gaRename = 1;
gaPageName = '/hs/cv/shinyugaku_setsumeikai_complete.html';
} else if (gPathName.indexOf(gBasePATH + '/form/zaitaku/form.php') != -1) {
gZaitaku = 1;
gaPageName = '/hs/vod/shiryou_entry.html';
} else if (
gPathName.indexOf('service.toshin.com/guest/check_values') != -1
) {
if (
typeof document.forms['myForm'] != 'undefined' &&
typeof document.forms['myForm'].elements['event_name'].value !=
'undefined'
) {
eventName2 = document.forms['myForm'].elements['event_name'].value;
if (eventName2 == 'siryou_vod' || eventName2 == 'siryou_vodkoza') {
gZaitaku = 1;
gaPageName = '/hs/vod/shiryou_confirm.html';
}
}
} else if (gPathName.indexOf('/ikueisha/inquiry/') != -1) {
gIkuei = 1;
}
}

//  GoogleTagManager
(function (w, d, s, l, i) {
w[l] = w[l] || [];
w[l].push({ 'gtm.start': new Date().getTime(), 'event': 'gtm.js' });
var f = d.getElementsByTagName(s)[0],
j = d.createElement(s),
dl = l != 'dataLayer' ? '&l=' + l : '';
j.async = true;
j.src = '//www.googletagmanager.com/gtm.js?id=' + i + dl;
f.parentNode.insertBefore(j, f);
})(window, document, 'script', 'dataLayer', GTM_id);

// www.toshin.com
if (
document.domain == 'www.toshin.com' ||
document.domain == 'service.toshin.com' ||
document.domain == 'pos.toshin.com'
) {
// =============================================================================
//   カスタム変数
// =============================================================================
//        var now = new Date();
// grade
if (gPathName.indexOf('/grade_h3/') != -1) {
_gaq.push(['_setCustomVar', 2, 'grade', 'h3', 1]);
$customer = 'h3';
} else if (gPathName.indexOf('/grade_h2/') != -1) {
_gaq.push(['_setCustomVar', 2, 'grade', 'h2', 1]);
$customer = 'h2';
} else if (gPathName.indexOf('/grade_h1/') != -1) {
_gaq.push(['_setCustomVar', 2, 'grade', 'h1', 1]);
$customer = 'h1';
} else if (gPathName.indexOf('/chugaku/') != -1) {
_gaq.push(['_setCustomVar', 2, 'grade', 'chugaku', 1]);
$customer = 'chugaku';
} else if (gPathName.indexOf('/honka/') != -1) {
_gaq.push(['_setCustomVar', 2, 'grade', 'honka', 1]);
$customer = 'honka';
} else if (gPathName.indexOf('/bs/univ_english/') != -1) {
_gaq.push(['_setCustomVar', 2, 'grade', 'univ', 1]);
$customer = 'univ';
} else if (
gPathName.indexOf('service.toshin.com/guest/regist_user') != -1 &&
typeof webID != 'undefined'
) {
_gaq.push(['_setCustomVar', 5, 'webid', webID, 1]);
if (typeof schoolname != 'undefined') {
_gaq.push(['_setCustomVar', 6, 'school', schoolname, 1]);
}
}

// イベント
if (typeof eventName != 'undefined') {
//            $date.now = dateFormat(now);
}

// 在宅GTM
if (gZaitaku) {
(function (w, d, s, l, i) {
w[l] = w[l] || [];
w[l].push({ 'gtm.start': new Date().getTime(), 'event': 'gtm.js' });
var f = d.getElementsByTagName(s)[0],
j = d.createElement(s),
dl = l != 'dataLayer' ? '&l=' + l : '';
j.async = true;
j.src = 'https://www.googletagmanager.com/gtm.js?id=' + i + dl;
f.parentNode.insertBefore(j, f);
})(window, document, 'script', 'dataLayer', 'GTM-M7DFND');
}
// 育英舎GTM
if (gIkuei) {
(function (w, d, s, l, i) {
w[l] = w[l] || [];
w[l].push({ 'gtm.start': new Date().getTime(), 'event': 'gtm.js' });
var f = d.getElementsByTagName(s)[0],
j = d.createElement(s),
dl = l != 'dataLayer' ? '&l=' + l : '';
j.async = true;
j.src = 'https://www.googletagmanager.com/gtm.js?id=' + i + dl;
f.parentNode.insertBefore(j, f);
})(window, document, 'script', 'dataLayer', 'GTM-KVV63LV');
}
}

function ga_event(category, action, label) {
window.dataLayer = window.dataLayer || [];
dataLayer.push({
event: 'gaqPush',
eventCategory: category,
eventAction: action,
eventLavel: label,
});
}
}

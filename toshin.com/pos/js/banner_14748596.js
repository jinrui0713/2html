// JavaScript Document

$(document).ready(function() {
  //初期設定
  var ad_banner_change_time = 5400; //タイマーの時間
  var ad_banner_animation_speed = 500; //アニメーションの速さ

  //自動解析
  var disparea_ad_banner_html = '<div id="ad_banner_disp"></div>';
  var ad_banner_html = $('#ad_banner').html();
  $('#ad_banner').html(ad_banner_html + disparea_ad_banner_html);

  $('#ad_banner_disp').insertBefore('#ad_banner');
  var num_of_disp_ad_banner = $('#ad_banner li').size();
  var ad_banner_now_disp_flag = num_of_disp_ad_banner;
  var ad_banner_clone = $('#ad_banner').html();
  $('#ad_banner_disp').html('<ul id="ad_banner">' + ad_banner_clone + ad_banner_clone + ad_banner_clone + '</ul>')
  var num_of_ad_banner = $('#ad_banner_disp #ad_banner li').size();
  $('#ad_banner_disp #ad_banner').css({ 'width': ($('#ad_banner_disp #ad_banner li').outerWidth({ margin: true }) * num_of_ad_banner) });

  //アニメーション部
  function ad_banner_animetion(num) {
    $(document).stopTime('ad_banner_timer01'); //一旦タイマー解除

    if (num == 'next') {
      ad_banner_now_disp_flag += 1;
      num = ad_banner_now_disp_flag;
    } else if (num == 'prev') {
      ad_banner_now_disp_flag -= 1;
      num = ad_banner_now_disp_flag;
    }
    $('#ad_banner_disp #ad_banner').animate({ 'margin-left': 0 - (($('#ad_banner_disp #ad_banner li').outerWidth({ margin: true }) * num) + ($('#ad_banner_disp #ad_banner li').innerWidth() / 2)) }, {
      duration: ad_banner_animation_speed,
      complete: function() {
        //処理終了時に実行
        if (num < num_of_disp_ad_banner) {
          ad_banner_now_disp_flag = (num + num_of_disp_ad_banner);
          $('#ad_banner_disp #ad_banner').css({ 'margin-left': 0 - (($('#ad_banner_disp #ad_banner li').outerWidth({ margin: true }) * ad_banner_now_disp_flag) + ($('#ad_banner_disp #ad_banner li').innerWidth() / 2)) });
        } else if (num >= (num_of_disp_ad_banner * 2)) {
          ad_banner_now_disp_flag = (num - num_of_disp_ad_banner);
          $('#ad_banner_disp #ad_banner').css({ 'margin-left': 0 - (($('#ad_banner_disp #ad_banner li').outerWidth({ margin: true }) * ad_banner_now_disp_flag) + ($('#ad_banner_disp #ad_banner li').innerWidth() / 2)) });
        }
      },
      queue: false //「true=古いキューを優先」「false=古いキューを削除」
    });
  }

  //初期動作
  ad_banner_animetion(ad_banner_now_disp_flag);

  //タイマー
  function ad_banner_start_timer() {
    $(document).everyTime(ad_banner_change_time, 'ad_banner_timer01', function() {
      ad_banner_now_disp_flag += 1
      ad_banner_animetion(ad_banner_now_disp_flag);
    });
  }

  //クリック動作
  $('.pos-banner-button-right').click(function() {
    ad_banner_animetion('next');
  });
  $('.pos-banner-button-left').click(function() {
    ad_banner_animetion('prev');
  });
});
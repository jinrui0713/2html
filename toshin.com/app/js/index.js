// ------------------------- index.php -------------------------
$(document).ready(function() {
  //1段階目のタブ
  $('#eitango-1800-btn').click(function() {
    $('#apri-left').children().hide();
    $('#eitango-1800').show();
    set_tab_img('eitango-1800');
    set_r_tab_img('eitango-1800');
    switch_tab(1);
  }).click();
  $('#jukugo-750-btn').click(function() {
    $('#apri-left').children().hide();
    $('#jukugo-750').show();
    set_tab_img('jukugo-750');
    set_r_tab_img('jukugo-750');
    switch_tab(1);
  });
  $('#bunpou-750-btn').click(function() {
    $('#apri-left').children().hide();
    $('#bunpou-750').show();
    set_tab_img('bunpou-750');
    set_r_tab_img('bunpou-750');
    switch_tab(1);
  });
  $('#reibun-300-btn').click(function() {
    $('#apri-left').children().hide();
    $('#reibun-300').show();
    set_tab_img('reibun-300');
    set_r_tab_img('reibun-300');
    switch_tab(1);
  });
  $('#business4002-btn').click(function() {
    $('#apri-left').children().hide();
    $('#business4002').show();
    set_tab_img('business4002');
    set_r_tab_img('business4002');
    switch_tab(1);
  });


  //2段階目
  function set_tab_img(type) {
    $('#tab1-bt').children('img').attr('src', 'img/tab1_' + type + 'app/_on.png');
  }

  function set_r_tab_img(type) {
    let app_list = new Array('eitango-1800', 'jukugo-750', 'bunpou-750', 'reibun-300', 'business4002');
    for (let i = 0; i < app_list.length; i++) {
      //on
      if (app_list[i] === type) {
        //onにする
        let onImgUrl = $('#' + app_list[i] + '-btn').children('img').attr('src').replace(/\app/_off.png/ig, 'app/_on.png');
        $('#' + app_list[i] + '-btn').children('img').attr('src', onImgUrl);
      }
      else {
        //offにする
        let onImgUrl = $('#' + app_list[i] + '-btn').children('img').attr('src').replace(/\app/_on.png/ig, 'app/_off.png');
        $('#' + app_list[i] + '-btn').children('img').attr('src', onImgUrl);
      }
    }
  }

  function switch_tab(num) {
    for (let i = 1; i < 4; i++) {
      if (i === num) {
        $('.tab-' + i).show();
        let onImgUrl = $('#tab' + i + '-bt').children('img').attr('src').replace(/\app/_off.png/ig, 'app/_on.png');
        $('#tab' + i + '-bt').children('img').attr('src', onImgUrl);
      }
      else {
        $('.tab-' + i).hide();
        let onImgUrl = $('#tab' + i + '-bt').children('img').attr('src').replace(/\app/_on.png/ig, 'app/_off.png');
        $('#tab' + i + '-bt').children('img').attr('src', onImgUrl);
      }
    }
  }

  $('#tab1-bt').click(function() {
    switch_tab(1);
  });
  $('#tab2-bt').click(function() {
    switch_tab(2);
  });
  $('#tab3-bt').click(function() {
    switch_tab(3);
  });
});

// -------------------------main_visual.php-------------------------
$(document).ready(function() {

  let num = 12;
  let screen_shots = new Array(num);
  let animete_pos = 0;
  for (let i = 0; i < num; i++) {
    screen_shots[i] = ('0' + (i + 1)).slice(-2) + '.png';
  }
  img_init();
  move_next(0);
  setInterval(function() {
    move_next('slow');
  }, 2000);

  //初期設定を行う
  function img_init() {
    let screen_shot_area = $('#screen-shots')
    let style = 'float:left;width:220px;';
    //+-10で表示範囲分余分に
    screen_shot_area.css('width', ((num + 20) * 220) + 'px');
    for (let i = 0; i < num + 20; i++) {
      screen_shot_area.append('<div style="' + style + '"><img src="./img/main_visual/screen/' + screen_shots[i % num] + '"></div>');
    }
  }

  //次の画面にアニメーションする
  function move_next(time){
    animete_pos++;
    $('#screen-shots').animate({
      left: (-36 - 220 * (animete_pos)) + 'px'
    }, time, function() {
      if (animete_pos === num) {
        animete_pos = 0;
        $('#screen-shots').css('left', '-36px');
      }
    });
    let screen_shots = $('#screen-shots').children().first();
    for (let i = 0; i < num + 20; i++) {
      if (animete_pos % num === (num + i - 2) % num) {
        screen_shots.animate({
          opacity: '1.0'
        }, time);
      } else {
        screen_shots.animate({
          opacity: '0.5'
        }, time);
      }
      screen_shots = screen_shots.next();
    }
  }
});

// -------------------------fancybox-------------------------
$(document).ready(function() {
  $('#fancyImage01').fancybox();
  $('#fancyImage02').fancybox();
  $('#fancyImage03').fancybox();
  $('#fancyImage04').fancybox();
  $('#fancyImage05').fancybox();
});

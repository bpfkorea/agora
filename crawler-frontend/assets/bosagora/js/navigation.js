import * as WowNS from '../../3rdparty/js/wow.min.js'

/*** Methods related to page navigation ***/

function scroll_to(clicked_link, nav_height) {
    var element_class = clicked_link.attr('href').replace('#', '.');
    var scroll_to = 0;

    scroll_to = $(element_class).offset().top - nav_height;

    if ($(window).scrollTop() != scroll_to) {
        $('html, body').stop().animate({ scrollTop: scroll_to }, 1000);
    }
}

jQuery(document).ready(function () {

    // Setting up scrolling and also hiding the navbar automatically after
    // clicking on the link
    $('a.scroll-link').on('click', function (e) {
        e.preventDefault();
        let navbar_visible = $('#btnNav').is(':visible');
        if (navbar_visible)
            $('#navbarNav').collapse('hide')
        scroll_to($(this), $('nav').outerHeight());
    });

    // Clicking on the breadcrumb should make the navbar non-transparent
    $('#btnNav').on('click', function (e) {
        let dropdown_visible = !($('#navbarNav').is(':visible'));
        if (dropdown_visible)
            $("nav").removeClass("navbar-no-bg")
        else
            changeNavBarVisibilityOnTop()
    });

    // Navigation bar should be transparent when on top
    document.addEventListener('scroll', function (e) {
        changeNavBarVisibilityOnTop();
    })

    // Setting up WoW
    new WowNS.WOW().init();

    google.charts.load('current', { 'packages': ['corechart', 'table'] });
    google.charts.setOnLoadCallback(window.startDrawing);

});

// Navigation bar should be transparent when on top
function changeNavBarVisibilityOnTop() {
    if (window.scrollY == 0)
        $("nav").addClass("navbar-no-bg")
    else
        $("nav").removeClass("navbar-no-bg")
}

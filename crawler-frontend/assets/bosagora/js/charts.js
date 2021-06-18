let callback_call_cnt = 0;

function startDrawing(return_quick) {

    // this function needs to be called by both
    // 1. Google maps after it is initialized
    // 2. Google chart after it is initialized
    // before the drawing can begin
    if (++callback_call_cnt != 2)
        return;

    let crawl_results = loadData();

    drawMap(crawl_results);
    drawGeoTable(crawl_results);
    drawOSTable(crawl_results);
    drawOSPieChart(crawl_results);
    drawClientTable(crawl_results);
    drawClientPieChart(crawl_results);
    drawNetworkTable(crawl_results);
    drawNetworkPieChart(crawl_results);
    drawHeightBarChart(crawl_results);
}

// webpack puts the entire content of this file into an IIFE block, but
// `startDrawing` should be accessible as a callback in multiple places
window.startDrawing = startDrawing;

// partition crawling results with same field values, and return the size of
// each partition similarly to `select count(*) group by (x, y, z...)` SQL query
function groupByField(crawl_results, field_names) {
    let crawl_results_vals = Object.keys(crawl_results).map(key => crawl_results[key])

    let field_cnt = crawl_results_vals.reduce((acc, crawl_result) => {
        let field_val = field_names.map(field_name => crawl_result[field_name]).join("-");
        field_val = field_val.substring(0, 26);
        if (!acc.hasOwnProperty(field_val)) {
            acc[field_val] = 0;
        }
        acc[field_val]++;
        return acc;
    }, {})

    return Object.keys(field_cnt).map(key => [key, field_cnt[key]])
}

/*** Geo ***/

function drawGeoTable(crawl_results) {
    let country_arr = groupByField(crawl_results, ["country"])

    let data = new google.visualization.DataTable();
    data.addColumn('string', 'Country');
    data.addColumn('number', '#Nodes ');
    data.addRows(country_arr);

    var cssClassNames = {
        headerRow: 'header-row-style',
        tableRow: 'row-style',
        oddTableRow: 'row-style',
        hoverTableRow: 'row-style',
        selectedTableRow: 'row-style',
        headerCell: 'header-cell-style',
        tableCell: 'table-cell-style'
    };

    var options = {
        showRowNumber: false,
        width: '100%',
        height: '100%',
        allowHtml: false,
        cssClassNames: cssClassNames,
        sortAscending: false,
        sortColumn: 1
    };

    let table = new google.visualization.Table(document.getElementById('geotable'));

    table.draw(data, options);
}

function drawMap(crawl_results) {

    let map = new google.maps.Map(document.getElementById('map'), {
        center: new google.maps.LatLng(43.809602, 68.990333),
        zoom: 2,
        mapTypeId: 'satellite'
    });

    var heatmap = new google.maps.visualization.HeatmapLayer({
        data: getCoordinates(crawl_results)
    });

    changeGradient(heatmap);
    changeRadius(heatmap);
    changeOpacity(heatmap);
    heatmap.setMap(map);
    google.maps.event.trigger(map, 'resize')

}

/*** OS ***/

function drawOSTable(crawl_results) {

    let os_arr = groupByField(crawl_results, ["os"])

    let data = new google.visualization.DataTable();
    data.addColumn('string', 'OS');
    data.addColumn('number', '#Nodes');
    data.addRows(os_arr);

    let cssClassNames = {
        tableCell: 'stats-table-cell-style'
    };

    let options = {
        showRowNumber: false,
        cssClassNames: cssClassNames,
        sortAscending: false,
        sortColumn: 1
    };

    let table = new google.visualization.Table(document.getElementById('osTable'));

    table.draw(data, options);
}

function drawOSPieChart(crawl_results) {

    let os_arr = groupByField(crawl_results, ["os"])

    let data = new google.visualization.DataTable();
    data.addColumn('string', 'OS');
    data.addColumn('number', '#Nodes');
    data.addRows(os_arr);

    let options = {
        backgroundColor: 'transparent',
        is3D: true
    };

    let chart = new google.visualization.PieChart(document.getElementById('osPieChart'));

    chart.draw(data, options);
}

/*** Clients ***/

function drawClientTable(crawl_results) {

    let os_arr = groupByField(crawl_results, ["client_name", "client_ver"])

    let data = new google.visualization.DataTable();
    data.addColumn('string', 'Client version');
    data.addColumn('number', '#Nodes');
    data.addRows(os_arr);

    let cssClassNames = {
        tableCell: 'stats-table-cell-style'
    };

    let options = {
        showRowNumber: false,
        cssClassNames: cssClassNames,
        sortAscending: false,
        sortColumn: 1
    };

    let table = new google.visualization.Table(document.getElementById('clientTable'));

    table.draw(data, options);
}

function drawClientPieChart(crawl_results) {

    let os_arr = groupByField(crawl_results, ["client_name", "client_ver"])

    let data = new google.visualization.DataTable();
    data.addColumn('string', 'Client version');
    data.addColumn('number', '#Nodes ');
    data.addRows(os_arr);

    var options = {
        backgroundColor: 'transparent',
        is3D: true
    };

    var chart = new google.visualization.PieChart(document.getElementById('clientPieChart'));

    chart.draw(data, options);
}


/*** Network ***/

function drawNetworkTable(crawl_results) {

    let network_arr = groupByField(crawl_results, ["is_ipv4"]).map(e => [(e[0] === "true"?"IPv4":"IPv6"),e[1]])

    let data = new google.visualization.DataTable();
    data.addColumn('string', 'Network');
    data.addColumn('number', '#Nodes');
    data.addRows(network_arr);

    let cssClassNames = {
        tableCell: 'stats-table-cell-style'
    };

    let options = {
        showRowNumber: false,
        cssClassNames: cssClassNames,
        sortAscending: false,
        sortColumn: 1
    };

    let table = new google.visualization.Table(document.getElementById('networkTable'));

    table.draw(data, options);
}

function drawNetworkPieChart(crawl_results) {

    let network_arr = groupByField(crawl_results, ["is_ipv4"]).map(e => [(e[0] === "true"?"IPv4":"IPv6"),e[1]])

    let data = new google.visualization.DataTable();
    data.addColumn('string', 'Network');
    data.addColumn('number', '#Nodes ');
    data.addRows(network_arr);

    var options = {
        backgroundColor: 'transparent',
        is3D: true
    };

    var chart = new google.visualization.PieChart(document.getElementById('networkPieChart'));

    chart.draw(data, options);
}

/*** Height ***/

function drawHeightBarChart(crawl_results) {

    let height_arr = groupByField(crawl_results, ["height"])

    // detect the most probable height of the blockchain by finding the most frequently
    // appearing height
    let max_height = parseInt(height_arr.slice().sort((a,b) => b[1] - a[1])[0][0]);

    let bar_cnt = 50;
    // only show values around the most probable height of the blockchain
    height_arr = height_arr.filter(e => ((e[0] <= max_height + 1) && (e[0] >= max_height - bar_cnt - 2)))

    // sort array by decreasing height
    height_arr.sort((a,b) => b[0] - a[0]);

    let data = new google.visualization.DataTable();
    data.addColumn('string', 'Height');
    data.addColumn('number', '#Node');
    data.addRows(height_arr);

    var options = {
        backgroundColor: 'transparent',
        legend: {
            position: 'top',
        },
        hAxis: {
            title: 'Height',
        }
    };

    var chart = new google.visualization.ColumnChart(document.getElementById('heightBarChart'));
    chart.draw(data, options);
}

/*** Utility ***/

// return an array of LatLng objects corresponding to nodes geo coordinates
function getCoordinates(crawl_results) {
    let test_data = []
    for (const [ip, crawl_result] of Object.entries(crawl_results)) {
        test_data.push(new google.maps.LatLng(crawl_result.latitude, crawl_result.longitude));
    }

    return test_data;
}

// load crawling result from an Agora instance
function loadData() {
    let res = $.ajax({
        dataType: "json",
        url: window.agora_node_endpoint,
        async: false, // there is nothing to work on until the data arrives
    });
    return JSON.parse(res.responseText).crawl_results;
}

// change Google heatmap gradient
function changeGradient(heatmap) {
    var gradient = [
        'rgba(0, 255, 255, 0)',
        'rgba(0, 255, 255, 1)',
        'rgba(0, 191, 255, 1)',
        'rgba(0, 127, 255, 1)',
        'rgba(0, 63, 255, 1)',
        'rgba(0, 0, 255, 1)',
        'rgba(0, 0, 223, 1)',
        'rgba(0, 0, 191, 1)',
        'rgba(0, 0, 159, 1)',
        'rgba(0, 0, 127, 1)',
        'rgba(63, 0, 91, 1)',
        'rgba(127, 0, 63, 1)',
        'rgba(191, 0, 31, 1)',
        'rgba(255, 0, 0, 1)'
    ]
    heatmap.set('gradient', heatmap.get('gradient') ? null : gradient);
}

// change Google heatmap radius
function changeRadius(heatmap) {
    heatmap.set('radius', heatmap.get('radius') ? null : 20);
}

// change Google heatmap opacity
function changeOpacity(heatmap) {
    heatmap.set('opacity', heatmap.get('opacity') ? null : 0.5);
}

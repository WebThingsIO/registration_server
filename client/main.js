let loadJSON = function(method, url, content = '') {
  return new Promise((resolve, reject) => {
    let xhr = new XMLHttpRequest();
    xhr.open(method, url, true);
    xhr.responseType = 'json';
    xhr.timeout = 3000;
    xhr.overrideMimeType('application/json');
    xhr.setRequestHeader('Accept', 'application/json,text/javascript,*/*;q=0.01');
    xhr.addEventListener('load', () => {
      if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
        resolve(xhr.response);
      } else {
        reject('Could not complete the operation.');
      }
    });
    xhr.addEventListener('error', reject);
    xhr.send(JSON.stringify(content));
  });
};

function doDiscovery() {
  console.log("Starting discovery.");
  loadJSON("GET", "http://cloud.desre.org:4242/ping").then(data => {
    console.log("Got data: " + JSON.stringify(data));

    if (!data) {
      return;
    }

    var content = "";
    data.forEach(item => {
      content += `<p>FoxBox found at ${item.local_ip}</p>`;
      loadJSON("GET", `http://${item.local_ip}:3000/services/list.json`).then(list => {
        console.log("Service list: " + JSON.stringify(list));
        let html = "<ul>";
        for (let s in list) {
          console.log("We have " + s);
          html += `<li>${list[s].name}</li>`;
        }
        html += "<ul>";
        document.getElementById("content").innerHTML += html;
      });
    });

    document.getElementById("content").innerHTML = content;
  });
}

window.addEventListener("DOMContentLoaded", () => {
  document.getElementById("go").addEventListener("click", doDiscovery);
});

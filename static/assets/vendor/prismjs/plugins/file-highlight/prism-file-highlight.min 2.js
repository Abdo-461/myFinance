"undefined"!=typeof self&&self.Prism&&self.document&&document.querySelector&&(self.Prism.fileHighlight=function(e){e=e||document;var i={js:"javascript",py:"python",rb:"ruby",ps1:"powershell",psm1:"powershell",sh:"bash",bat:"batch",h:"c",tex:"latex"};Array.prototype.slice.call(e.querySelectorAll("pre[data-src]")).forEach(function(e){if(!e.hasAttribute("data-src-loaded")){for(var t,a=e.getAttribute("data-src"),s=e,n=/\blang(?:uage)?-([\w-]+)\b/i;s&&!n.test(s.className);)s=s.parentNode;if(s&&(t=(e.className.match(n)||[,""])[1]),!t){var r=(a.match(/\.(\w+)$/)||[,""])[1];t=i[r]||r}var o=document.createElement("code");o.className="language-"+t,e.textContent="",o.textContent="Loading…",e.appendChild(o);var l=new XMLHttpRequest;l.open("GET",a,!0),l.onreadystatechange=function(){4==l.readyState&&(l.status<400&&l.responseText?(o.textContent=l.responseText,Prism.highlightElement(o),e.setAttribute("data-src-loaded","")):400<=l.status?o.textContent="✖ Error "+l.status+" while fetching file: "+l.statusText:o.textContent="✖ Error: File does not exist or is empty")},l.send(null)}})},document.addEventListener("DOMContentLoaded",function(){self.Prism.fileHighlight()}));
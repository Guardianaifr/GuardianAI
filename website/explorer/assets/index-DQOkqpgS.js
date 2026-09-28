const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["./add-B0EedGzw.js","./core-g_yxChh4.js","./index-BKZ1AJiu.js","./index-BOOBCn-Q.css","./all-wallets-DyyWdx_N.js","./arrow-bottom-circle-BZ7SKdrF.js","./app-store-Dje_ak-J.js","./apple-bhT7WdOl.js","./arrow-bottom-B5GRx4Ll.js","./arrow-left-5Ld73j0G.js","./arrow-right-tYpT_uP0.js","./arrow-top-A_qkzZAc.js","./bank-BBK4y6Ta.js","./browser-pHq8YJWY.js","./card-fQLR82gr.js","./checkmark-9MTaFNoq.js","./checkmark-bold-Dd9CT6lr.js","./chevron-bottom-jJQoa7Lu.js","./chevron-left-DQKjeJCl.js","./chevron-right-C89UOLOW.js","./chevron-top-DAhL3OM7.js","./chrome-store-BIGNJhR9.js","./clock-BOmmeLiK.js","./close-BDAoGso5.js","./compass-B6uZUTAL.js","./coinPlaceholder-C2gF2e_j.js","./copy-DordwcrM.js","./cursor-DeT-lN2P.js","./cursor-transparent-rADxQHQk.js","./desktop-B5C5BL1i.js","./disconnect-DXhobsah.js","./discord-CDtGuvY9.js","./etherscan-YCaFhHwC.js","./extension-CdWABp8B.js","./external-link-BGVouXC3.js","./facebook-CF9scu9L.js","./farcaster-XHqKAXMw.js","./filters-BX63rBKA.js","./github-Dz9ldJ5j.js","./google-WwWoxqyD.js","./help-circle-CIskGqB2.js","./image-CRE88Lj1.js","./id-Cpny3NTU.js","./info-circle-D-KRlgmh.js","./lightbulb-DppmfXAR.js","./mail-C96qsUIg.js","./mobile-ZZyL8QZu.js","./more-C0HwRC1B.js","./network-placeholder-B06Rmkbs.js","./nftPlaceholder-umsv-sss.js","./off-nsBtzPYO.js","./play-store-CGjNIS6z.js","./plus-DivYHqjI.js","./qr-code-CdmNsTLx.js","./recycle-horizontal-Ufk4sm9M.js","./refresh-CfnqDdOu.js","./search-Fl2ZaYuS.js","./send-poqtQ-44.js","./swapHorizontal-CK-na5XB.js","./swapHorizontalMedium-BDZTUyF0.js","./swapHorizontalBold-CiM10kxc.js","./swapHorizontalRoundedBold-BCQPkl7A.js","./swapVertical-dusI7L-9.js","./telegram-9ygNCpBo.js","./three-dots-D6u22s4z.js","./twitch-DRzHsCWo.js","./x-DI-VnP2B.js","./twitterIcon-DoAarkdN.js","./verify-DnkJfkCl.js","./verify-filled-B3_PaZRJ.js","./wallet-D0Rk7hBM.js","./walletconnect-BCdB7GeD.js","./wallet-placeholder-BeKLdgPh.js","./warning-circle-BTRPrxRw.js","./info-CEea8l7C.js","./exclamation-triangle-De53XuP2.js","./reown-logo-B1KxRjSQ.js"])))=>i.map(i=>d[i]);
import{B as N,D as q,i as S,r as b,a as E,b as w,n as Y,F as V,o as H,e as X}from"./core-g_yxChh4.js";import{aY as a}from"./index-BKZ1AJiu.js";const v={getSpacingStyles(t,e){if(Array.isArray(t))return t[e]?`var(--wui-spacing-${t[e]})`:void 0;if(typeof t=="string")return`var(--wui-spacing-${t})`},getFormattedDate(t){return new Intl.DateTimeFormat("en-US",{month:"short",day:"numeric"}).format(t)},getHostName(t){try{return new URL(t).hostname}catch{return""}},getTruncateString({string:t,charsStart:e,charsEnd:r,truncate:i}){return t.length<=e+r?t:i==="end"?`${t.substring(0,e)}...`:i==="start"?`...${t.substring(t.length-r)}`:`${t.substring(0,Math.floor(e))}...${t.substring(t.length-Math.floor(r))}`},generateAvatarColors(t){const r=t.toLowerCase().replace(/^0x/iu,"").replace(/[^a-f0-9]/gu,"").substring(0,6).padEnd(6,"0"),i=this.hexToRgb(r),n=getComputedStyle(document.documentElement).getPropertyValue("--w3m-border-radius-master"),c=100-3*Number(n?.replace("px","")),s=`${c}% ${c}% at 65% 40%`,u=[];for(let g=0;g<5;g+=1){const _=this.tintColor(i,.15*g);u.push(`rgb(${_[0]}, ${_[1]}, ${_[2]})`)}return`
    --local-color-1: ${u[0]};
    --local-color-2: ${u[1]};
    --local-color-3: ${u[2]};
    --local-color-4: ${u[3]};
    --local-color-5: ${u[4]};
    --local-radial-circle: ${s}
   `},hexToRgb(t){const e=parseInt(t,16),r=e>>16&255,i=e>>8&255,n=e&255;return[r,i,n]},tintColor(t,e){const[r,i,n]=t,o=Math.round(r+(255-r)*e),c=Math.round(i+(255-i)*e),s=Math.round(n+(255-n)*e);return[o,c,s]},isNumber(t){return{number:/^[0-9]+$/u}.number.test(t)},getColorTheme(t){return t||(typeof window<"u"&&window.matchMedia?window.matchMedia("(prefers-color-scheme: dark)")?.matches?"dark":"light":"dark")},splitBalance(t){const e=t.split(".");return e.length===2?[e[0],e[1]]:["0","00"]},roundNumber(t,e,r){return t.toString().length>=e?Number(t).toFixed(r):t},formatNumberToLocalString(t,e=2){return t===void 0?"0.00":typeof t=="number"?t.toLocaleString("en-US",{maximumFractionDigits:e,minimumFractionDigits:e}):parseFloat(t).toLocaleString("en-US",{maximumFractionDigits:e,minimumFractionDigits:e})}};function K(t,e){const{kind:r,elements:i}=e;return{kind:r,elements:i,finisher(n){customElements.get(t)||customElements.define(t,n)}}}function Z(t,e){return customElements.get(t)||customElements.define(t,e),e}function $(t){return function(r){return typeof r=="function"?Z(t,r):K(t,r)}}const Q={attribute:!0,type:String,converter:q,reflect:!1,hasChanged:N},J=(t=Q,e,r)=>{const{kind:i,metadata:n}=r;let o=globalThis.litPropertyMetadata.get(n);if(o===void 0&&globalThis.litPropertyMetadata.set(n,o=new Map),i==="setter"&&((t=Object.create(t)).wrapped=!0),o.set(r.name,t),i==="accessor"){const{name:c}=r;return{set(s){const u=e.get.call(this);e.set.call(this,s),this.requestUpdate(c,u,t,!0,s)},init(s){return s!==void 0&&this.C(c,void 0,t,s),s}}}if(i==="setter"){const{name:c}=r;return function(s){const u=this[c];e.call(this,s),this.requestUpdate(c,u,t,!0,s)}}throw Error("Unsupported decorator location: "+i)};function l(t){return(e,r)=>typeof r=="object"?J(t,e,r):((i,n,o)=>{const c=n.hasOwnProperty(o);return n.constructor.createProperty(o,i),c?Object.getOwnPropertyDescriptor(n,o):void 0})(t,e,r)}function bt(t){return l({...t,state:!0,attribute:!1})}const tt=S`
  :host {
    display: flex;
    width: inherit;
    height: inherit;
  }
`;var d=function(t,e,r,i){var n=arguments.length,o=n<3?e:i===null?i=Object.getOwnPropertyDescriptor(e,r):i,c;if(typeof Reflect=="object"&&typeof Reflect.decorate=="function")o=Reflect.decorate(t,e,r,i);else for(var s=t.length-1;s>=0;s--)(c=t[s])&&(o=(n<3?c(o):n>3?c(e,r,o):c(e,r))||o);return n>3&&o&&Object.defineProperty(e,r,o),o};let p=class extends E{render(){return this.style.cssText=`
      flex-direction: ${this.flexDirection};
      flex-wrap: ${this.flexWrap};
      flex-basis: ${this.flexBasis};
      flex-grow: ${this.flexGrow};
      flex-shrink: ${this.flexShrink};
      align-items: ${this.alignItems};
      justify-content: ${this.justifyContent};
      column-gap: ${this.columnGap&&`var(--wui-spacing-${this.columnGap})`};
      row-gap: ${this.rowGap&&`var(--wui-spacing-${this.rowGap})`};
      gap: ${this.gap&&`var(--wui-spacing-${this.gap})`};
      padding-top: ${this.padding&&v.getSpacingStyles(this.padding,0)};
      padding-right: ${this.padding&&v.getSpacingStyles(this.padding,1)};
      padding-bottom: ${this.padding&&v.getSpacingStyles(this.padding,2)};
      padding-left: ${this.padding&&v.getSpacingStyles(this.padding,3)};
      margin-top: ${this.margin&&v.getSpacingStyles(this.margin,0)};
      margin-right: ${this.margin&&v.getSpacingStyles(this.margin,1)};
      margin-bottom: ${this.margin&&v.getSpacingStyles(this.margin,2)};
      margin-left: ${this.margin&&v.getSpacingStyles(this.margin,3)};
    `,w`<slot></slot>`}};p.styles=[b,tt];d([l()],p.prototype,"flexDirection",void 0);d([l()],p.prototype,"flexWrap",void 0);d([l()],p.prototype,"flexBasis",void 0);d([l()],p.prototype,"flexGrow",void 0);d([l()],p.prototype,"flexShrink",void 0);d([l()],p.prototype,"alignItems",void 0);d([l()],p.prototype,"justifyContent",void 0);d([l()],p.prototype,"columnGap",void 0);d([l()],p.prototype,"rowGap",void 0);d([l()],p.prototype,"gap",void 0);d([l()],p.prototype,"padding",void 0);d([l()],p.prototype,"margin",void 0);p=d([$("wui-flex")],p);const $t=t=>t??Y;const et=t=>t===null||typeof t!="object"&&typeof t!="function",rt=t=>t.strings===void 0;const W={ATTRIBUTE:1,CHILD:2},U=t=>(...e)=>({_$litDirective$:t,values:e});let F=class{constructor(e){}get _$AU(){return this._$AM._$AU}_$AT(e,r,i){this._$Ct=e,this._$AM=r,this._$Ci=i}_$AS(e,r){return this.update(e,r)}update(e,r){return this.render(...r)}};const R=(t,e)=>{const r=t._$AN;if(r===void 0)return!1;for(const i of r)i._$AO?.(e,!1),R(i,e);return!0},I=t=>{let e,r;do{if((e=t._$AM)===void 0)break;r=e._$AN,r.delete(t),t=e}while(r?.size===0)},G=t=>{for(let e;e=t._$AM;t=e){let r=e._$AN;if(r===void 0)e._$AN=r=new Set;else if(r.has(t))break;r.add(t),at(e)}};function it(t){this._$AN!==void 0?(I(this),this._$AM=t,G(this)):this._$AM=t}function ot(t,e=!1,r=0){const i=this._$AH,n=this._$AN;if(n!==void 0&&n.size!==0)if(e)if(Array.isArray(i))for(let o=r;o<i.length;o++)R(i[o],!1),I(i[o]);else i!=null&&(R(i,!1),I(i));else R(this,t)}const at=t=>{t.type==W.CHILD&&(t._$AP??=ot,t._$AQ??=it)};class nt extends F{constructor(){super(...arguments),this._$AN=void 0}_$AT(e,r,i){super._$AT(e,r,i),G(this),this.isConnected=e._$AU}_$AO(e,r=!0){e!==this.isConnected&&(this.isConnected=e,e?this.reconnected?.():this.disconnected?.()),r&&(R(this,e),I(this))}setValue(e){if(rt(this._$Ct))this._$Ct._$AI(e,this);else{const r=[...this._$Ct._$AH];r[this._$Ci]=e,this._$Ct._$AI(r,this,0)}}disconnected(){}reconnected(){}}class st{constructor(e){this.G=e}disconnect(){this.G=void 0}reconnect(e){this.G=e}deref(){return this.G}}class ct{constructor(){this.Y=void 0,this.Z=void 0}get(){return this.Y}pause(){this.Y??=new Promise(e=>this.Z=e)}resume(){this.Z?.(),this.Y=this.Z=void 0}}const j=t=>!et(t)&&typeof t.then=="function",B=1073741823;class lt extends nt{constructor(){super(...arguments),this._$Cwt=B,this._$Cbt=[],this._$CK=new st(this),this._$CX=new ct}render(...e){return e.find(r=>!j(r))??V}update(e,r){const i=this._$Cbt;let n=i.length;this._$Cbt=r;const o=this._$CK,c=this._$CX;this.isConnected||this.disconnected();for(let s=0;s<r.length&&!(s>this._$Cwt);s++){const u=r[s];if(!j(u))return this._$Cwt=s,u;s<n&&u===i[s]||(this._$Cwt=B,n=0,Promise.resolve(u).then(async g=>{for(;c.get();)await c.get();const _=o.deref();if(_!==void 0){const C=_._$Cbt.indexOf(u);C>-1&&C<_._$Cwt&&(_._$Cwt=C,_.setValue(g))}}))}return V}disconnected(){this._$CK.disconnect(),this._$CX.pause()}reconnected(){this._$CK.reconnect(this),this._$CX.resume()}}const ut=U(lt);class pt{constructor(){this.cache=new Map}set(e,r){this.cache.set(e,r)}get(e){return this.cache.get(e)}has(e){return this.cache.has(e)}delete(e){this.cache.delete(e)}clear(){this.cache.clear()}}const D=new pt,dt=S`
  :host {
    display: flex;
    aspect-ratio: var(--local-aspect-ratio);
    color: var(--local-color);
    width: var(--local-width);
  }

  svg {
    width: inherit;
    height: inherit;
    object-fit: contain;
    object-position: center;
  }

  .fallback {
    width: var(--local-width);
    height: var(--local-height);
  }
`;var P=function(t,e,r,i){var n=arguments.length,o=n<3?e:i,c;if(typeof Reflect=="object"&&typeof Reflect.decorate=="function")o=Reflect.decorate(t,e,r,i);else for(var s=t.length-1;s>=0;s--)(c=t[s])&&(o=(n<3?c(o):n>3?c(e,r,o):c(e,r))||o);return n>3&&o&&Object.defineProperty(e,r,o),o};const M={add:async()=>(await a(async()=>{const{addSvg:t}=await import("./add-B0EedGzw.js");return{addSvg:t}},__vite__mapDeps([0,1,2,3]),import.meta.url)).addSvg,allWallets:async()=>(await a(async()=>{const{allWalletsSvg:t}=await import("./all-wallets-DyyWdx_N.js");return{allWalletsSvg:t}},__vite__mapDeps([4,1,2,3]),import.meta.url)).allWalletsSvg,arrowBottomCircle:async()=>(await a(async()=>{const{arrowBottomCircleSvg:t}=await import("./arrow-bottom-circle-BZ7SKdrF.js");return{arrowBottomCircleSvg:t}},__vite__mapDeps([5,1,2,3]),import.meta.url)).arrowBottomCircleSvg,appStore:async()=>(await a(async()=>{const{appStoreSvg:t}=await import("./app-store-Dje_ak-J.js");return{appStoreSvg:t}},__vite__mapDeps([6,1,2,3]),import.meta.url)).appStoreSvg,apple:async()=>(await a(async()=>{const{appleSvg:t}=await import("./apple-bhT7WdOl.js");return{appleSvg:t}},__vite__mapDeps([7,1,2,3]),import.meta.url)).appleSvg,arrowBottom:async()=>(await a(async()=>{const{arrowBottomSvg:t}=await import("./arrow-bottom-B5GRx4Ll.js");return{arrowBottomSvg:t}},__vite__mapDeps([8,1,2,3]),import.meta.url)).arrowBottomSvg,arrowLeft:async()=>(await a(async()=>{const{arrowLeftSvg:t}=await import("./arrow-left-5Ld73j0G.js");return{arrowLeftSvg:t}},__vite__mapDeps([9,1,2,3]),import.meta.url)).arrowLeftSvg,arrowRight:async()=>(await a(async()=>{const{arrowRightSvg:t}=await import("./arrow-right-tYpT_uP0.js");return{arrowRightSvg:t}},__vite__mapDeps([10,1,2,3]),import.meta.url)).arrowRightSvg,arrowTop:async()=>(await a(async()=>{const{arrowTopSvg:t}=await import("./arrow-top-A_qkzZAc.js");return{arrowTopSvg:t}},__vite__mapDeps([11,1,2,3]),import.meta.url)).arrowTopSvg,bank:async()=>(await a(async()=>{const{bankSvg:t}=await import("./bank-BBK4y6Ta.js");return{bankSvg:t}},__vite__mapDeps([12,1,2,3]),import.meta.url)).bankSvg,browser:async()=>(await a(async()=>{const{browserSvg:t}=await import("./browser-pHq8YJWY.js");return{browserSvg:t}},__vite__mapDeps([13,1,2,3]),import.meta.url)).browserSvg,card:async()=>(await a(async()=>{const{cardSvg:t}=await import("./card-fQLR82gr.js");return{cardSvg:t}},__vite__mapDeps([14,1,2,3]),import.meta.url)).cardSvg,checkmark:async()=>(await a(async()=>{const{checkmarkSvg:t}=await import("./checkmark-9MTaFNoq.js");return{checkmarkSvg:t}},__vite__mapDeps([15,1,2,3]),import.meta.url)).checkmarkSvg,checkmarkBold:async()=>(await a(async()=>{const{checkmarkBoldSvg:t}=await import("./checkmark-bold-Dd9CT6lr.js");return{checkmarkBoldSvg:t}},__vite__mapDeps([16,1,2,3]),import.meta.url)).checkmarkBoldSvg,chevronBottom:async()=>(await a(async()=>{const{chevronBottomSvg:t}=await import("./chevron-bottom-jJQoa7Lu.js");return{chevronBottomSvg:t}},__vite__mapDeps([17,1,2,3]),import.meta.url)).chevronBottomSvg,chevronLeft:async()=>(await a(async()=>{const{chevronLeftSvg:t}=await import("./chevron-left-DQKjeJCl.js");return{chevronLeftSvg:t}},__vite__mapDeps([18,1,2,3]),import.meta.url)).chevronLeftSvg,chevronRight:async()=>(await a(async()=>{const{chevronRightSvg:t}=await import("./chevron-right-C89UOLOW.js");return{chevronRightSvg:t}},__vite__mapDeps([19,1,2,3]),import.meta.url)).chevronRightSvg,chevronTop:async()=>(await a(async()=>{const{chevronTopSvg:t}=await import("./chevron-top-DAhL3OM7.js");return{chevronTopSvg:t}},__vite__mapDeps([20,1,2,3]),import.meta.url)).chevronTopSvg,chromeStore:async()=>(await a(async()=>{const{chromeStoreSvg:t}=await import("./chrome-store-BIGNJhR9.js");return{chromeStoreSvg:t}},__vite__mapDeps([21,1,2,3]),import.meta.url)).chromeStoreSvg,clock:async()=>(await a(async()=>{const{clockSvg:t}=await import("./clock-BOmmeLiK.js");return{clockSvg:t}},__vite__mapDeps([22,1,2,3]),import.meta.url)).clockSvg,close:async()=>(await a(async()=>{const{closeSvg:t}=await import("./close-BDAoGso5.js");return{closeSvg:t}},__vite__mapDeps([23,1,2,3]),import.meta.url)).closeSvg,compass:async()=>(await a(async()=>{const{compassSvg:t}=await import("./compass-B6uZUTAL.js");return{compassSvg:t}},__vite__mapDeps([24,1,2,3]),import.meta.url)).compassSvg,coinPlaceholder:async()=>(await a(async()=>{const{coinPlaceholderSvg:t}=await import("./coinPlaceholder-C2gF2e_j.js");return{coinPlaceholderSvg:t}},__vite__mapDeps([25,1,2,3]),import.meta.url)).coinPlaceholderSvg,copy:async()=>(await a(async()=>{const{copySvg:t}=await import("./copy-DordwcrM.js");return{copySvg:t}},__vite__mapDeps([26,1,2,3]),import.meta.url)).copySvg,cursor:async()=>(await a(async()=>{const{cursorSvg:t}=await import("./cursor-DeT-lN2P.js");return{cursorSvg:t}},__vite__mapDeps([27,1,2,3]),import.meta.url)).cursorSvg,cursorTransparent:async()=>(await a(async()=>{const{cursorTransparentSvg:t}=await import("./cursor-transparent-rADxQHQk.js");return{cursorTransparentSvg:t}},__vite__mapDeps([28,1,2,3]),import.meta.url)).cursorTransparentSvg,desktop:async()=>(await a(async()=>{const{desktopSvg:t}=await import("./desktop-B5C5BL1i.js");return{desktopSvg:t}},__vite__mapDeps([29,1,2,3]),import.meta.url)).desktopSvg,disconnect:async()=>(await a(async()=>{const{disconnectSvg:t}=await import("./disconnect-DXhobsah.js");return{disconnectSvg:t}},__vite__mapDeps([30,1,2,3]),import.meta.url)).disconnectSvg,discord:async()=>(await a(async()=>{const{discordSvg:t}=await import("./discord-CDtGuvY9.js");return{discordSvg:t}},__vite__mapDeps([31,1,2,3]),import.meta.url)).discordSvg,etherscan:async()=>(await a(async()=>{const{etherscanSvg:t}=await import("./etherscan-YCaFhHwC.js");return{etherscanSvg:t}},__vite__mapDeps([32,1,2,3]),import.meta.url)).etherscanSvg,extension:async()=>(await a(async()=>{const{extensionSvg:t}=await import("./extension-CdWABp8B.js");return{extensionSvg:t}},__vite__mapDeps([33,1,2,3]),import.meta.url)).extensionSvg,externalLink:async()=>(await a(async()=>{const{externalLinkSvg:t}=await import("./external-link-BGVouXC3.js");return{externalLinkSvg:t}},__vite__mapDeps([34,1,2,3]),import.meta.url)).externalLinkSvg,facebook:async()=>(await a(async()=>{const{facebookSvg:t}=await import("./facebook-CF9scu9L.js");return{facebookSvg:t}},__vite__mapDeps([35,1,2,3]),import.meta.url)).facebookSvg,farcaster:async()=>(await a(async()=>{const{farcasterSvg:t}=await import("./farcaster-XHqKAXMw.js");return{farcasterSvg:t}},__vite__mapDeps([36,1,2,3]),import.meta.url)).farcasterSvg,filters:async()=>(await a(async()=>{const{filtersSvg:t}=await import("./filters-BX63rBKA.js");return{filtersSvg:t}},__vite__mapDeps([37,1,2,3]),import.meta.url)).filtersSvg,github:async()=>(await a(async()=>{const{githubSvg:t}=await import("./github-Dz9ldJ5j.js");return{githubSvg:t}},__vite__mapDeps([38,1,2,3]),import.meta.url)).githubSvg,google:async()=>(await a(async()=>{const{googleSvg:t}=await import("./google-WwWoxqyD.js");return{googleSvg:t}},__vite__mapDeps([39,1,2,3]),import.meta.url)).googleSvg,helpCircle:async()=>(await a(async()=>{const{helpCircleSvg:t}=await import("./help-circle-CIskGqB2.js");return{helpCircleSvg:t}},__vite__mapDeps([40,1,2,3]),import.meta.url)).helpCircleSvg,image:async()=>(await a(async()=>{const{imageSvg:t}=await import("./image-CRE88Lj1.js");return{imageSvg:t}},__vite__mapDeps([41,1,2,3]),import.meta.url)).imageSvg,id:async()=>(await a(async()=>{const{idSvg:t}=await import("./id-Cpny3NTU.js");return{idSvg:t}},__vite__mapDeps([42,1,2,3]),import.meta.url)).idSvg,infoCircle:async()=>(await a(async()=>{const{infoCircleSvg:t}=await import("./info-circle-D-KRlgmh.js");return{infoCircleSvg:t}},__vite__mapDeps([43,1,2,3]),import.meta.url)).infoCircleSvg,lightbulb:async()=>(await a(async()=>{const{lightbulbSvg:t}=await import("./lightbulb-DppmfXAR.js");return{lightbulbSvg:t}},__vite__mapDeps([44,1,2,3]),import.meta.url)).lightbulbSvg,mail:async()=>(await a(async()=>{const{mailSvg:t}=await import("./mail-C96qsUIg.js");return{mailSvg:t}},__vite__mapDeps([45,1,2,3]),import.meta.url)).mailSvg,mobile:async()=>(await a(async()=>{const{mobileSvg:t}=await import("./mobile-ZZyL8QZu.js");return{mobileSvg:t}},__vite__mapDeps([46,1,2,3]),import.meta.url)).mobileSvg,more:async()=>(await a(async()=>{const{moreSvg:t}=await import("./more-C0HwRC1B.js");return{moreSvg:t}},__vite__mapDeps([47,1,2,3]),import.meta.url)).moreSvg,networkPlaceholder:async()=>(await a(async()=>{const{networkPlaceholderSvg:t}=await import("./network-placeholder-B06Rmkbs.js");return{networkPlaceholderSvg:t}},__vite__mapDeps([48,1,2,3]),import.meta.url)).networkPlaceholderSvg,nftPlaceholder:async()=>(await a(async()=>{const{nftPlaceholderSvg:t}=await import("./nftPlaceholder-umsv-sss.js");return{nftPlaceholderSvg:t}},__vite__mapDeps([49,1,2,3]),import.meta.url)).nftPlaceholderSvg,off:async()=>(await a(async()=>{const{offSvg:t}=await import("./off-nsBtzPYO.js");return{offSvg:t}},__vite__mapDeps([50,1,2,3]),import.meta.url)).offSvg,playStore:async()=>(await a(async()=>{const{playStoreSvg:t}=await import("./play-store-CGjNIS6z.js");return{playStoreSvg:t}},__vite__mapDeps([51,1,2,3]),import.meta.url)).playStoreSvg,plus:async()=>(await a(async()=>{const{plusSvg:t}=await import("./plus-DivYHqjI.js");return{plusSvg:t}},__vite__mapDeps([52,1,2,3]),import.meta.url)).plusSvg,qrCode:async()=>(await a(async()=>{const{qrCodeIcon:t}=await import("./qr-code-CdmNsTLx.js");return{qrCodeIcon:t}},__vite__mapDeps([53,1,2,3]),import.meta.url)).qrCodeIcon,recycleHorizontal:async()=>(await a(async()=>{const{recycleHorizontalSvg:t}=await import("./recycle-horizontal-Ufk4sm9M.js");return{recycleHorizontalSvg:t}},__vite__mapDeps([54,1,2,3]),import.meta.url)).recycleHorizontalSvg,refresh:async()=>(await a(async()=>{const{refreshSvg:t}=await import("./refresh-CfnqDdOu.js");return{refreshSvg:t}},__vite__mapDeps([55,1,2,3]),import.meta.url)).refreshSvg,search:async()=>(await a(async()=>{const{searchSvg:t}=await import("./search-Fl2ZaYuS.js");return{searchSvg:t}},__vite__mapDeps([56,1,2,3]),import.meta.url)).searchSvg,send:async()=>(await a(async()=>{const{sendSvg:t}=await import("./send-poqtQ-44.js");return{sendSvg:t}},__vite__mapDeps([57,1,2,3]),import.meta.url)).sendSvg,swapHorizontal:async()=>(await a(async()=>{const{swapHorizontalSvg:t}=await import("./swapHorizontal-CK-na5XB.js");return{swapHorizontalSvg:t}},__vite__mapDeps([58,1,2,3]),import.meta.url)).swapHorizontalSvg,swapHorizontalMedium:async()=>(await a(async()=>{const{swapHorizontalMediumSvg:t}=await import("./swapHorizontalMedium-BDZTUyF0.js");return{swapHorizontalMediumSvg:t}},__vite__mapDeps([59,1,2,3]),import.meta.url)).swapHorizontalMediumSvg,swapHorizontalBold:async()=>(await a(async()=>{const{swapHorizontalBoldSvg:t}=await import("./swapHorizontalBold-CiM10kxc.js");return{swapHorizontalBoldSvg:t}},__vite__mapDeps([60,1,2,3]),import.meta.url)).swapHorizontalBoldSvg,swapHorizontalRoundedBold:async()=>(await a(async()=>{const{swapHorizontalRoundedBoldSvg:t}=await import("./swapHorizontalRoundedBold-BCQPkl7A.js");return{swapHorizontalRoundedBoldSvg:t}},__vite__mapDeps([61,1,2,3]),import.meta.url)).swapHorizontalRoundedBoldSvg,swapVertical:async()=>(await a(async()=>{const{swapVerticalSvg:t}=await import("./swapVertical-dusI7L-9.js");return{swapVerticalSvg:t}},__vite__mapDeps([62,1,2,3]),import.meta.url)).swapVerticalSvg,telegram:async()=>(await a(async()=>{const{telegramSvg:t}=await import("./telegram-9ygNCpBo.js");return{telegramSvg:t}},__vite__mapDeps([63,1,2,3]),import.meta.url)).telegramSvg,threeDots:async()=>(await a(async()=>{const{threeDotsSvg:t}=await import("./three-dots-D6u22s4z.js");return{threeDotsSvg:t}},__vite__mapDeps([64,1,2,3]),import.meta.url)).threeDotsSvg,twitch:async()=>(await a(async()=>{const{twitchSvg:t}=await import("./twitch-DRzHsCWo.js");return{twitchSvg:t}},__vite__mapDeps([65,1,2,3]),import.meta.url)).twitchSvg,twitter:async()=>(await a(async()=>{const{xSvg:t}=await import("./x-DI-VnP2B.js");return{xSvg:t}},__vite__mapDeps([66,1,2,3]),import.meta.url)).xSvg,twitterIcon:async()=>(await a(async()=>{const{twitterIconSvg:t}=await import("./twitterIcon-DoAarkdN.js");return{twitterIconSvg:t}},__vite__mapDeps([67,1,2,3]),import.meta.url)).twitterIconSvg,verify:async()=>(await a(async()=>{const{verifySvg:t}=await import("./verify-DnkJfkCl.js");return{verifySvg:t}},__vite__mapDeps([68,1,2,3]),import.meta.url)).verifySvg,verifyFilled:async()=>(await a(async()=>{const{verifyFilledSvg:t}=await import("./verify-filled-B3_PaZRJ.js");return{verifyFilledSvg:t}},__vite__mapDeps([69,1,2,3]),import.meta.url)).verifyFilledSvg,wallet:async()=>(await a(async()=>{const{walletSvg:t}=await import("./wallet-D0Rk7hBM.js");return{walletSvg:t}},__vite__mapDeps([70,1,2,3]),import.meta.url)).walletSvg,walletConnect:async()=>(await a(async()=>{const{walletConnectSvg:t}=await import("./walletconnect-BCdB7GeD.js");return{walletConnectSvg:t}},__vite__mapDeps([71,1,2,3]),import.meta.url)).walletConnectSvg,walletConnectLightBrown:async()=>(await a(async()=>{const{walletConnectLightBrownSvg:t}=await import("./walletconnect-BCdB7GeD.js");return{walletConnectLightBrownSvg:t}},__vite__mapDeps([71,1,2,3]),import.meta.url)).walletConnectLightBrownSvg,walletConnectBrown:async()=>(await a(async()=>{const{walletConnectBrownSvg:t}=await import("./walletconnect-BCdB7GeD.js");return{walletConnectBrownSvg:t}},__vite__mapDeps([71,1,2,3]),import.meta.url)).walletConnectBrownSvg,walletPlaceholder:async()=>(await a(async()=>{const{walletPlaceholderSvg:t}=await import("./wallet-placeholder-BeKLdgPh.js");return{walletPlaceholderSvg:t}},__vite__mapDeps([72,1,2,3]),import.meta.url)).walletPlaceholderSvg,warningCircle:async()=>(await a(async()=>{const{warningCircleSvg:t}=await import("./warning-circle-BTRPrxRw.js");return{warningCircleSvg:t}},__vite__mapDeps([73,1,2,3]),import.meta.url)).warningCircleSvg,x:async()=>(await a(async()=>{const{xSvg:t}=await import("./x-DI-VnP2B.js");return{xSvg:t}},__vite__mapDeps([66,1,2,3]),import.meta.url)).xSvg,info:async()=>(await a(async()=>{const{infoSvg:t}=await import("./info-CEea8l7C.js");return{infoSvg:t}},__vite__mapDeps([74,1,2,3]),import.meta.url)).infoSvg,exclamationTriangle:async()=>(await a(async()=>{const{exclamationTriangleSvg:t}=await import("./exclamation-triangle-De53XuP2.js");return{exclamationTriangleSvg:t}},__vite__mapDeps([75,1,2,3]),import.meta.url)).exclamationTriangleSvg,reown:async()=>(await a(async()=>{const{reownSvg:t}=await import("./reown-logo-B1KxRjSQ.js");return{reownSvg:t}},__vite__mapDeps([76,1,2,3]),import.meta.url)).reownSvg};async function mt(t){if(D.has(t))return D.get(t);const r=(M[t]??M.copy)();return D.set(t,r),r}let f=class extends E{constructor(){super(...arguments),this.size="md",this.name="copy",this.color="fg-300",this.aspectRatio="1 / 1"}render(){return this.style.cssText=`
      --local-color: ${`var(--wui-color-${this.color});`}
      --local-width: ${`var(--wui-icon-size-${this.size});`}
      --local-aspect-ratio: ${this.aspectRatio}
    `,w`${ut(mt(this.name),w`<div class="fallback"></div>`)}`}};f.styles=[b,H,dt];P([l()],f.prototype,"size",void 0);P([l()],f.prototype,"name",void 0);P([l()],f.prototype,"color",void 0);P([l()],f.prototype,"aspectRatio",void 0);f=P([$("wui-icon")],f);const gt=U(class extends F{constructor(t){if(super(t),t.type!==W.ATTRIBUTE||t.name!=="class"||t.strings?.length>2)throw Error("`classMap()` can only be used in the `class` attribute and must be the only part in the attribute.")}render(t){return" "+Object.keys(t).filter(e=>t[e]).join(" ")+" "}update(t,[e]){if(this.st===void 0){this.st=new Set,t.strings!==void 0&&(this.nt=new Set(t.strings.join(" ").split(/\s/).filter(i=>i!=="")));for(const i in e)e[i]&&!this.nt?.has(i)&&this.st.add(i);return this.render(e)}const r=t.element.classList;for(const i of this.st)i in e||(r.remove(i),this.st.delete(i));for(const i in e){const n=!!e[i];n===this.st.has(i)||this.nt?.has(i)||(n?(r.add(i),this.st.add(i)):(r.remove(i),this.st.delete(i)))}return V}}),_t=S`
  :host {
    display: inline-flex !important;
  }

  slot {
    width: 100%;
    display: inline-block;
    font-style: normal;
    font-family: var(--wui-font-family);
    font-feature-settings:
      'tnum' on,
      'lnum' on,
      'case' on;
    line-height: 130%;
    font-weight: var(--wui-font-weight-regular);
    overflow: inherit;
    text-overflow: inherit;
    text-align: var(--local-align);
    color: var(--local-color);
  }

  .wui-line-clamp-1 {
    overflow: hidden;
    display: -webkit-box;
    -webkit-box-orient: vertical;
    -webkit-line-clamp: 1;
  }

  .wui-line-clamp-2 {
    overflow: hidden;
    display: -webkit-box;
    -webkit-box-orient: vertical;
    -webkit-line-clamp: 2;
  }

  .wui-font-medium-400 {
    font-size: var(--wui-font-size-medium);
    font-weight: var(--wui-font-weight-light);
    letter-spacing: var(--wui-letter-spacing-medium);
  }

  .wui-font-medium-600 {
    font-size: var(--wui-font-size-medium);
    letter-spacing: var(--wui-letter-spacing-medium);
  }

  .wui-font-title-600 {
    font-size: var(--wui-font-size-title);
    letter-spacing: var(--wui-letter-spacing-title);
  }

  .wui-font-title-6-600 {
    font-size: var(--wui-font-size-title-6);
    letter-spacing: var(--wui-letter-spacing-title-6);
  }

  .wui-font-mini-700 {
    font-size: var(--wui-font-size-mini);
    letter-spacing: var(--wui-letter-spacing-mini);
    text-transform: uppercase;
  }

  .wui-font-large-500,
  .wui-font-large-600,
  .wui-font-large-700 {
    font-size: var(--wui-font-size-large);
    letter-spacing: var(--wui-letter-spacing-large);
  }

  .wui-font-2xl-500,
  .wui-font-2xl-600,
  .wui-font-2xl-700 {
    font-size: var(--wui-font-size-2xl);
    letter-spacing: var(--wui-letter-spacing-2xl);
  }

  .wui-font-paragraph-400,
  .wui-font-paragraph-500,
  .wui-font-paragraph-600,
  .wui-font-paragraph-700 {
    font-size: var(--wui-font-size-paragraph);
    letter-spacing: var(--wui-letter-spacing-paragraph);
  }

  .wui-font-small-400,
  .wui-font-small-500,
  .wui-font-small-600 {
    font-size: var(--wui-font-size-small);
    letter-spacing: var(--wui-letter-spacing-small);
  }

  .wui-font-tiny-400,
  .wui-font-tiny-500,
  .wui-font-tiny-600 {
    font-size: var(--wui-font-size-tiny);
    letter-spacing: var(--wui-letter-spacing-tiny);
  }

  .wui-font-micro-700,
  .wui-font-micro-600 {
    font-size: var(--wui-font-size-micro);
    letter-spacing: var(--wui-letter-spacing-micro);
    text-transform: uppercase;
  }

  .wui-font-tiny-400,
  .wui-font-small-400,
  .wui-font-medium-400,
  .wui-font-paragraph-400 {
    font-weight: var(--wui-font-weight-light);
  }

  .wui-font-large-700,
  .wui-font-paragraph-700,
  .wui-font-micro-700,
  .wui-font-mini-700 {
    font-weight: var(--wui-font-weight-bold);
  }

  .wui-font-medium-600,
  .wui-font-medium-title-600,
  .wui-font-title-6-600,
  .wui-font-large-600,
  .wui-font-paragraph-600,
  .wui-font-small-600,
  .wui-font-tiny-600,
  .wui-font-micro-600 {
    font-weight: var(--wui-font-weight-medium);
  }

  :host([disabled]) {
    opacity: 0.4;
  }
`;var O=function(t,e,r,i){var n=arguments.length,o=n<3?e:i===null?i=Object.getOwnPropertyDescriptor(e,r):i,c;if(typeof Reflect=="object"&&typeof Reflect.decorate=="function")o=Reflect.decorate(t,e,r,i);else for(var s=t.length-1;s>=0;s--)(c=t[s])&&(o=(n<3?c(o):n>3?c(e,r,o):c(e,r))||o);return n>3&&o&&Object.defineProperty(e,r,o),o};let y=class extends E{constructor(){super(...arguments),this.variant="paragraph-500",this.color="fg-300",this.align="left",this.lineClamp=void 0}render(){const e={[`wui-font-${this.variant}`]:!0,[`wui-color-${this.color}`]:!0,[`wui-line-clamp-${this.lineClamp}`]:!!this.lineClamp};return this.style.cssText=`
      --local-align: ${this.align};
      --local-color: var(--wui-color-${this.color});
    `,w`<slot class=${gt(e)}></slot>`}};y.styles=[b,_t];O([l()],y.prototype,"variant",void 0);O([l()],y.prototype,"color",void 0);O([l()],y.prototype,"align",void 0);O([l()],y.prototype,"lineClamp",void 0);y=O([$("wui-text")],y);const ht=S`
  :host {
    display: inline-flex;
    justify-content: center;
    align-items: center;
    position: relative;
    overflow: hidden;
    background-color: var(--wui-color-gray-glass-020);
    border-radius: var(--local-border-radius);
    border: var(--local-border);
    box-sizing: content-box;
    width: var(--local-size);
    height: var(--local-size);
    min-height: var(--local-size);
    min-width: var(--local-size);
  }

  @supports (background: color-mix(in srgb, white 50%, black)) {
    :host {
      background-color: color-mix(in srgb, var(--local-bg-value) var(--local-bg-mix), transparent);
    }
  }
`;var h=function(t,e,r,i){var n=arguments.length,o=n<3?e:i===null?i=Object.getOwnPropertyDescriptor(e,r):i,c;if(typeof Reflect=="object"&&typeof Reflect.decorate=="function")o=Reflect.decorate(t,e,r,i);else for(var s=t.length-1;s>=0;s--)(c=t[s])&&(o=(n<3?c(o):n>3?c(e,r,o):c(e,r))||o);return n>3&&o&&Object.defineProperty(e,r,o),o};let m=class extends E{constructor(){super(...arguments),this.size="md",this.backgroundColor="accent-100",this.iconColor="accent-100",this.background="transparent",this.border=!1,this.borderColor="wui-color-bg-125",this.icon="copy"}render(){const e=this.iconSize||this.size,r=this.size==="lg",i=this.size==="xl",n=r?"12%":"16%",o=r?"xxs":i?"s":"3xl",c=this.background==="gray",s=this.background==="opaque",u=this.backgroundColor==="accent-100"&&s||this.backgroundColor==="success-100"&&s||this.backgroundColor==="error-100"&&s||this.backgroundColor==="inverse-100"&&s;let g=`var(--wui-color-${this.backgroundColor})`;return u?g=`var(--wui-icon-box-bg-${this.backgroundColor})`:c&&(g=`var(--wui-color-gray-${this.backgroundColor})`),this.style.cssText=`
       --local-bg-value: ${g};
       --local-bg-mix: ${u||c?"100%":n};
       --local-border-radius: var(--wui-border-radius-${o});
       --local-size: var(--wui-icon-box-size-${this.size});
       --local-border: ${this.borderColor==="wui-color-bg-125"?"2px":"1px"} solid ${this.border?`var(--${this.borderColor})`:"transparent"}
   `,w` <wui-icon color=${this.iconColor} size=${e} name=${this.icon}></wui-icon> `}};m.styles=[b,X,ht];h([l()],m.prototype,"size",void 0);h([l()],m.prototype,"backgroundColor",void 0);h([l()],m.prototype,"iconColor",void 0);h([l()],m.prototype,"iconSize",void 0);h([l()],m.prototype,"background",void 0);h([l({type:Boolean})],m.prototype,"border",void 0);h([l()],m.prototype,"borderColor",void 0);h([l()],m.prototype,"icon",void 0);m=h([$("wui-icon-box")],m);const vt=S`
  :host {
    display: block;
    width: var(--local-width);
    height: var(--local-height);
  }

  img {
    display: block;
    width: 100%;
    height: 100%;
    object-fit: cover;
    object-position: center center;
    border-radius: inherit;
  }
`;var L=function(t,e,r,i){var n=arguments.length,o=n<3?e:i===null?i=Object.getOwnPropertyDescriptor(e,r):i,c;if(typeof Reflect=="object"&&typeof Reflect.decorate=="function")o=Reflect.decorate(t,e,r,i);else for(var s=t.length-1;s>=0;s--)(c=t[s])&&(o=(n<3?c(o):n>3?c(e,r,o):c(e,r))||o);return n>3&&o&&Object.defineProperty(e,r,o),o};let x=class extends E{constructor(){super(...arguments),this.src="./path/to/image.jpg",this.alt="Image",this.size=void 0}render(){return this.style.cssText=`
      --local-width: ${this.size?`var(--wui-icon-size-${this.size});`:"100%"};
      --local-height: ${this.size?`var(--wui-icon-size-${this.size});`:"100%"};
      `,w`<img src=${this.src} alt=${this.alt} @error=${this.handleImageError} />`}handleImageError(){this.dispatchEvent(new CustomEvent("onLoadError",{bubbles:!0,composed:!0}))}};x.styles=[b,H,vt];L([l()],x.prototype,"src",void 0);L([l()],x.prototype,"alt",void 0);L([l()],x.prototype,"size",void 0);x=L([$("wui-image")],x);const wt=S`
  :host {
    display: flex;
    justify-content: center;
    align-items: center;
    height: var(--wui-spacing-m);
    padding: 0 var(--wui-spacing-3xs) !important;
    border-radius: var(--wui-border-radius-5xs);
    transition:
      border-radius var(--wui-duration-lg) var(--wui-ease-out-power-1),
      background-color var(--wui-duration-lg) var(--wui-ease-out-power-1);
    will-change: border-radius, background-color;
  }

  :host > wui-text {
    transform: translateY(5%);
  }

  :host([data-variant='main']) {
    background-color: var(--wui-color-accent-glass-015);
    color: var(--wui-color-accent-100);
  }

  :host([data-variant='shade']) {
    background-color: var(--wui-color-gray-glass-010);
    color: var(--wui-color-fg-200);
  }

  :host([data-variant='success']) {
    background-color: var(--wui-icon-box-bg-success-100);
    color: var(--wui-color-success-100);
  }

  :host([data-variant='error']) {
    background-color: var(--wui-icon-box-bg-error-100);
    color: var(--wui-color-error-100);
  }

  :host([data-size='lg']) {
    padding: 11px 5px !important;
  }

  :host([data-size='lg']) > wui-text {
    transform: translateY(2%);
  }
`;var z=function(t,e,r,i){var n=arguments.length,o=n<3?e:i===null?i=Object.getOwnPropertyDescriptor(e,r):i,c;if(typeof Reflect=="object"&&typeof Reflect.decorate=="function")o=Reflect.decorate(t,e,r,i);else for(var s=t.length-1;s>=0;s--)(c=t[s])&&(o=(n<3?c(o):n>3?c(e,r,o):c(e,r))||o);return n>3&&o&&Object.defineProperty(e,r,o),o};let T=class extends E{constructor(){super(...arguments),this.variant="main",this.size="lg"}render(){this.dataset.variant=this.variant,this.dataset.size=this.size;const e=this.size==="md"?"mini-700":"micro-700";return w`
      <wui-text data-variant=${this.variant} variant=${e} color="inherit">
        <slot></slot>
      </wui-text>
    `}};T.styles=[b,wt];z([l()],T.prototype,"variant",void 0);z([l()],T.prototype,"size",void 0);T=z([$("wui-tag")],T);const ft=S`
  :host {
    display: flex;
  }

  :host([data-size='sm']) > svg {
    width: 12px;
    height: 12px;
  }

  :host([data-size='md']) > svg {
    width: 16px;
    height: 16px;
  }

  :host([data-size='lg']) > svg {
    width: 24px;
    height: 24px;
  }

  :host([data-size='xl']) > svg {
    width: 32px;
    height: 32px;
  }

  svg {
    animation: rotate 2s linear infinite;
  }

  circle {
    fill: none;
    stroke: var(--local-color);
    stroke-width: 4px;
    stroke-dasharray: 1, 124;
    stroke-dashoffset: 0;
    stroke-linecap: round;
    animation: dash 1.5s ease-in-out infinite;
  }

  :host([data-size='md']) > svg > circle {
    stroke-width: 6px;
  }

  :host([data-size='sm']) > svg > circle {
    stroke-width: 8px;
  }

  @keyframes rotate {
    100% {
      transform: rotate(360deg);
    }
  }

  @keyframes dash {
    0% {
      stroke-dasharray: 1, 124;
      stroke-dashoffset: 0;
    }

    50% {
      stroke-dasharray: 90, 124;
      stroke-dashoffset: -35;
    }

    100% {
      stroke-dashoffset: -125;
    }
  }
`;var k=function(t,e,r,i){var n=arguments.length,o=n<3?e:i===null?i=Object.getOwnPropertyDescriptor(e,r):i,c;if(typeof Reflect=="object"&&typeof Reflect.decorate=="function")o=Reflect.decorate(t,e,r,i);else for(var s=t.length-1;s>=0;s--)(c=t[s])&&(o=(n<3?c(o):n>3?c(e,r,o):c(e,r))||o);return n>3&&o&&Object.defineProperty(e,r,o),o};let A=class extends E{constructor(){super(...arguments),this.color="accent-100",this.size="lg"}render(){return this.style.cssText=`--local-color: ${this.color==="inherit"?"inherit":`var(--wui-color-${this.color})`}`,this.dataset.size=this.size,w`<svg viewBox="25 25 50 50">
      <circle r="20" cy="50" cx="50"></circle>
    </svg>`}};A.styles=[b,ft];k([l()],A.prototype,"color",void 0);k([l()],A.prototype,"size",void 0);A=k([$("wui-loading-spinner")],A);export{v as U,gt as a,$ as c,U as e,nt as f,l as n,$t as o,bt as r};

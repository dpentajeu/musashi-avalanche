(this["webpackJsonppancake-frontend"]=this["webpackJsonppancake-frontend"]||[]).push([[3],{793:function(e,t,n){"use strict";var r,c=n(8),i=n(4).e.span(r||(r=Object(c.a)(["\n  &::after {\n    display: inline-block;\n    animation: ellipsis 1.25s infinite;\n    content: '.';\n    width: 1em;\n    text-align: left;\n  }\n  @keyframes ellipsis {\n    0% {\n      content: '.';\n    }\n    33% {\n      content: '..';\n    }\n    66% {\n      content: '...';\n    }\n  }\n"])));t.a=i},794:function(e,t,n){"use strict";n.d(t,"a",(function(){return c}));var r=n(15);function c(e){if(e===r.d)return"BNB";if(e instanceof r.i)return e.address;throw new Error("invalid currency")}},797:function(e,t,n){"use strict";var r=n(15),c=n(34),i=n(69);t.a=function(e){var t,n,o=Object(c.r)(null===e||void 0===e?void 0:e.address,!1),a=null===(t=Object(i.c)(o,"totalSupply"))||void 0===t||null===(n=t.result)||void 0===n?void 0:n[0];return e&&a?new r.j(e,a.toString()):void 0}},804:function(e,t,n){"use strict";n.d(t,"a",(function(){return E})),n.d(t,"b",(function(){return C}));var r,c=n(6),i=n(48),o=n(13),a=n(8),l=n(0),s=n(15),u=n(5),d=n(85),b=n(4),j=n(22),O=n(29),f=n(797),x=n(787),p=n(794),v=n(201),h=n(792),m=n(58),g=n(791),y=n(784),w=n(19),k=n(94),S=n(793),T=n(1),N=["pair"],P=Object(b.e)(w.b)(r||(r=Object(a.a)(["\n  height: 24px;\n"])));function E(e){var t=e.pair,n=e.showUnwrapped,r=void 0!==n&&n,c=Object(O.a)().account,i=Object(j.b)().t,a=r?t.token0:Object(v.a)(t.token0),d=r?t.token1:Object(v.a)(t.token1),b=Object(l.useState)(!1),p=Object(o.a)(b,2),g=p[0],k=p[1],S=Object(x.d)(null!==c&&void 0!==c?c:void 0,t.liquidityToken),N=Object(f.a)(t.liquidityToken),E=S&&N&&s.e.greaterThanOrEqual(N.raw,S.raw)?new s.g(S.raw,N.raw):void 0,C=t&&N&&S&&s.e.greaterThanOrEqual(N.raw,S.raw)?[t.getLiquidityValue(t.token0,N,S,!1),t.getLiquidityValue(t.token1,N,S,!1)]:[void 0,void 0],A=Object(o.a)(C,2),I=A[0],B=A[1];return Object(T.jsx)(T.Fragment,{children:S&&s.e.greaterThan(S.raw,s.e.BigInt(0))?Object(T.jsx)(u.n,{children:Object(T.jsx)(u.o,{children:Object(T.jsxs)(m.a,{gap:"16px",children:[Object(T.jsx)(P,{children:Object(T.jsx)(w.c,{children:Object(T.jsx)(u.fb,{color:"secondary",bold:!0,children:i("LP tokens in your wallet")})})}),Object(T.jsxs)(P,{onClick:function(){return k(!g)},children:[Object(T.jsxs)(w.c,{children:[Object(T.jsx)(y.b,{currency0:a,currency1:d,margin:!0,size:20}),Object(T.jsxs)(u.fb,{small:!0,color:"textSubtle",children:[a.symbol,"-",d.symbol," LP"]})]}),Object(T.jsx)(w.c,{children:Object(T.jsx)(u.fb,{children:S?S.toSignificant(4):"-"})})]}),Object(T.jsxs)(m.a,{gap:"4px",children:[Object(T.jsxs)(P,{children:[Object(T.jsxs)(u.fb,{color:"textSubtle",small:!0,children:[i("Share of Pool"),":"]}),Object(T.jsx)(u.fb,{children:E?"".concat(E.toFixed(6),"%"):"-"})]}),Object(T.jsxs)(P,{children:[Object(T.jsxs)(u.fb,{color:"textSubtle",small:!0,children:[i("Pooled %asset%",{asset:a.symbol}),":"]}),I?Object(T.jsx)(w.c,{children:Object(T.jsx)(u.fb,{ml:"6px",children:null===I||void 0===I?void 0:I.toSignificant(6)})}):"-"]}),Object(T.jsxs)(P,{children:[Object(T.jsxs)(u.fb,{color:"textSubtle",small:!0,children:[i("Pooled %asset%",{asset:d.symbol}),":"]}),B?Object(T.jsx)(w.c,{children:Object(T.jsx)(u.fb,{ml:"6px",children:null===B||void 0===B?void 0:B.toSignificant(6)})}):"-"]})]})]})})}):Object(T.jsx)(h.a,{children:Object(T.jsxs)(u.fb,{fontSize:"14px",style:{textAlign:"center"},children:[Object(T.jsx)("span",{role:"img","aria-label":"pancake-icon",children:"\ud83e\udd5e"})," ",i("By adding liquidity you'll earn 0.17% of all trades on this pair proportional to your share of the pool. Fees are added to the pool, accrue in real time and can be claimed by withdrawing your liquidity.")]})})})}function C(e){var t=e.pair,n=Object(i.a)(e,N),r=Object(O.a)().account,a=Object(v.a)(t.token0),b=Object(v.a)(t.token1),j=Object(l.useState)(!1),h=Object(o.a)(j,2),E=h[0],C=h[1],A=Object(x.d)(null!==r&&void 0!==r?r:void 0,t.liquidityToken),I=Object(f.a)(t.liquidityToken),B=A&&I&&s.e.greaterThanOrEqual(I.raw,A.raw)?new s.g(A.raw,I.raw):void 0,M=t&&I&&A&&s.e.greaterThanOrEqual(I.raw,A.raw)?[t.getLiquidityValue(t.token0,I,A,!1),t.getLiquidityValue(t.token1,I,A,!1)]:[void 0,void 0],z=Object(o.a)(M,2),q=z[0],D=z[1];return Object(T.jsxs)(u.n,Object(c.a)(Object(c.a)({style:{borderRadius:"12px"}},n),{},{children:[Object(T.jsxs)(u.E,{justifyContent:"space-between",role:"button",onClick:function(){return C(!E)},p:"16px",children:[Object(T.jsxs)(u.E,{flexDirection:"column",children:[Object(T.jsxs)(u.E,{alignItems:"center",mb:"4px",children:[Object(T.jsx)(y.b,{currency0:a,currency1:b,size:20}),Object(T.jsx)(u.fb,{bold:!0,ml:"8px",children:a&&b?"".concat(a.symbol,"/").concat(b.symbol):Object(T.jsx)(S.a,{children:"Loading"})})]}),Object(T.jsx)(u.fb,{fontSize:"14px",color:"textSubtle",children:null===A||void 0===A?void 0:A.toSignificant(4)})]}),E?Object(T.jsx)(u.w,{}):Object(T.jsx)(u.u,{})]}),E&&Object(T.jsxs)(m.a,{gap:"8px",style:{padding:"16px"},children:[Object(T.jsxs)(P,{children:[Object(T.jsxs)(w.c,{children:[Object(T.jsx)(g.a,{size:"20px",currency:a}),Object(T.jsxs)(u.fb,{color:"textSubtle",ml:"4px",children:["Pooled ",a.symbol]})]}),q?Object(T.jsx)(w.c,{children:Object(T.jsx)(u.fb,{ml:"6px",children:null===q||void 0===q?void 0:q.toSignificant(6)})}):"-"]}),Object(T.jsxs)(P,{children:[Object(T.jsxs)(w.c,{children:[Object(T.jsx)(g.a,{size:"20px",currency:b}),Object(T.jsxs)(u.fb,{color:"textSubtle",ml:"4px",children:["Pooled ",b.symbol]})]}),D?Object(T.jsx)(w.c,{children:Object(T.jsx)(u.fb,{ml:"6px",children:null===D||void 0===D?void 0:D.toSignificant(6)})}):"-"]}),Object(T.jsxs)(P,{children:[Object(T.jsx)(u.fb,{color:"textSubtle",children:"Share of pool"}),Object(T.jsx)(u.fb,{children:B?"".concat("0.00"===B.toFixed(2)?"<0.01":B.toFixed(2),"%"):"-"})]}),A&&s.e.greaterThan(A.raw,k.h)&&Object(T.jsxs)(u.E,{flexDirection:"column",children:[Object(T.jsx)(u.k,{as:d.a,to:"/remove/".concat(Object(p.a)(a),"/").concat(Object(p.a)(b)),variant:"primary",width:"100%",mb:"8px",children:"Remove"}),Object(T.jsx)(u.k,{as:d.a,to:"/add/".concat(Object(p.a)(a),"/").concat(Object(p.a)(b)),variant:"text",startIcon:Object(T.jsx)(u.a,{color:"primary"}),width:"100%",children:"Add liquidity instead"})]})]})]}))}},805:function(e,t,n){"use strict";var r,c=n(6),i=n(48),o=n(8),a=(n(0),n(4)),l=n(22),s=n(1),u=["children"],d=a.e.div(r||(r=Object(o.a)(["\n  background-color: #910101;\n  padding-bottom: 60px;\n"])));t.a=function(e){var t=e.children,n=Object(i.a)(e,u),r=Object(l.b)().t;return Object(s.jsx)(s.Fragment,{children:Object(s.jsxs)(d,Object(c.a)(Object(c.a)({},n),{},{children:[Object(s.jsx)("h1",{className:"page-red-header hide-ifMobile",children:r("ZAP")}),Object(s.jsx)("div",{className:"swap-container",children:t})]}))})}},820:function(e,t,n){"use strict";n.d(t,"a",(function(){return s}));var r=n(14),c=n(15),i=(n(94),n(67)),o=n(78),a=new c.g(c.e.BigInt(25),c.e.BigInt(1e4)),l=new c.g(c.e.BigInt(1e4),c.e.BigInt(1e4));l.subtract(a);function s(e,t){var n,c=Object(o.a)(t);return n={},Object(r.a)(n,i.a.INPUT,null===e||void 0===e?void 0:e.maximumAmountIn(c)),Object(r.a)(n,i.a.OUTPUT,null===e||void 0===e?void 0:e.minimumAmountOut(c)),n}},828:function(e,t,n){"use strict";n.d(t,"b",(function(){return p})),n.d(t,"c",(function(){return v})),n.d(t,"a",(function(){return h}));var r=n(35),c=n(13),i=n(15),o=n(94);function a(e,t){var n=arguments.length>2&&void 0!==arguments[2]?arguments[2]:o.t;if(e&&!t)return!1;if(t&&!e)return!0;if(e&&t){if(e.tradeType!==t.tradeType||!Object(i.m)(e.inputAmount.currency,t.inputAmount.currency)||!Object(i.m)(t.outputAmount.currency,t.outputAmount.currency))throw new Error("Trades are not comparable");return n.equalTo(o.t)?e.executionPrice.lessThan(t.executionPrice):e.executionPrice.raw.multiply(n.add(o.p)).lessThan(t.executionPrice)}}var l=n(349),s=n.n(l),u=n(0),d=n(29),b=n(141),j=n(202),O=n(201),f=n(232);function x(e,t){var n=Object(d.a)().chainId,i=n?[Object(O.b)(e,n),Object(O.b)(t,n)]:[void 0,void 0],a=Object(c.a)(i,2),l=a[0],b=a[1],f=Object(u.useMemo)((function(){var e,t,c,i,a;if(!n)return[];var s=null!==(e=o.e[n])&&void 0!==e?e:[],u=l&&null!==(t=null===(c=o.a[n])||void 0===c?void 0:c[l.address])&&void 0!==t?t:[],d=b&&null!==(i=null===(a=o.a[n])||void 0===a?void 0:a[b.address])&&void 0!==i?i:[];return[].concat(Object(r.a)(s),Object(r.a)(u),Object(r.a)(d))}),[n,l,b]),x=Object(u.useMemo)((function(){return s()(f,(function(e){return f.map((function(t){return[e,t]}))}))}),[f]),p=Object(u.useMemo)((function(){return l&&b?[[l,b]].concat(Object(r.a)(f.map((function(e){return[l,e]}))),Object(r.a)(f.map((function(e){return[b,e]}))),Object(r.a)(x)).filter((function(e){return Boolean(e[0]&&e[1])})).filter((function(e){var t=Object(c.a)(e,2),n=t[0],r=t[1];return n.address!==r.address})).filter((function(e){var t=Object(c.a)(e,2),r=t[0],i=t[1];if(!n)return!0;var a=o.k[n],l=null===a||void 0===a?void 0:a[r.address],s=null===a||void 0===a?void 0:a[i.address];return!l&&!s||!(l&&!l.find((function(e){return i.equals(e)})))&&!(s&&!s.find((function(e){return r.equals(e)})))})):[]}),[l,b,f,x,n]),v=Object(j.c)(p);return Object(u.useMemo)((function(){return Object.values(v.filter((function(e){return Boolean(e[0]===j.a.EXISTS&&e[1])})).reduce((function(e,t){var n,r=Object(c.a)(t,2)[1];return e[r.liquidityToken.address]=null!==(n=e[r.liquidityToken.address])&&void 0!==n?n:r,e}),{}))}),[v])}function p(e,t){var n=x(null===e||void 0===e?void 0:e.currency,t),r=Object(b.i)(),l=Object(c.a)(r,1)[0];return Object(u.useMemo)((function(){if(e&&t&&n.length>0){var r;if(l)return null!==(r=i.k.bestTradeExactIn(n,e,t,{maxHops:1,maxNumResults:1})[0])&&void 0!==r?r:null;for(var c=null,s=1;s<=3;s++){var u,d=null!==(u=i.k.bestTradeExactIn(n,e,t,{maxHops:s,maxNumResults:1})[0])&&void 0!==u?u:null;a(c,d,o.g)&&(c=d)}return c}return null}),[n,e,t,l])}function v(e,t){var n=x(e,null===t||void 0===t?void 0:t.currency),r=Object(b.i)(),l=Object(c.a)(r,1)[0];return Object(u.useMemo)((function(){if(e&&t&&n.length>0){var r;if(l)return null!==(r=i.k.bestTradeExactOut(n,e,t,{maxHops:1,maxNumResults:1})[0])&&void 0!==r?r:null;for(var c=null,s=1;s<=3;s++){var u,d=null!==(u=i.k.bestTradeExactOut(n,e,t,{maxHops:s,maxNumResults:1})[0])&&void 0!==u?u:null;a(c,d,o.g)&&(c=d)}return c}return null}),[e,t,n,l])}function h(e,t){var n=Object(f.i)(),r=Object(d.a)().chainId,c=Object(O.b)(e,r),i=Object(O.b)(t,r);if(n){if(c&&Object.keys(n).includes(c.address))return!0;if(i&&Object.keys(n).includes(i.address))return!0}return!1}},829:function(e,t,n){"use strict";n.d(t,"a",(function(){return o}));var r=n(869),c=n(0),i=n(68);function o(){var e=Object(i.h)().search;return Object(c.useMemo)((function(){return e&&e.length>1?Object(r.parse)(e,{parseArrays:!1,ignoreQueryPrefix:!0}):{}}),[e])}},866:function(e,t,n){"use strict";n.d(t,"a",(function(){return u}));var r=n(78),c=n(161),i=n(0),o=n(69),a=n(795),l=n(34),s=n(235);function u(e){var t=Object(r.h)(e),n=function(e){var t,n,u,d=Object(s.a)(e,200),b=Object(i.useMemo)((function(){if(!d||!Object(r.h)(d))return[void 0];try{return d?[Object(c.namehash)("".concat(d.toLowerCase().substr(2),".addr.reverse"))]:[void 0]}catch(e){return[void 0]}}),[d]),j=Object(l.e)(!1),O=Object(o.c)(j,"resolver",b),f=null===(t=O.result)||void 0===t?void 0:t[0],x=Object(l.f)(f&&!Object(a.a)(f)?f:void 0,!1),p=Object(o.c)(x,"name",b),v=d!==e;return{ENSName:v?null:null!==(n=null===(u=p.result)||void 0===u?void 0:u[0])&&void 0!==n?n:null,loading:v||O.loading||p.loading}}(t||void 0),u=function(e){var t,n,r,u=Object(s.a)(e,200),d=Object(i.useMemo)((function(){if(!u)return[void 0];try{return u?[Object(c.namehash)(u)]:[void 0]}catch(e){return[void 0]}}),[u]),b=Object(l.e)(!1),j=Object(o.c)(b,"resolver",d),O=null===(t=j.result)||void 0===t?void 0:t[0],f=Object(l.f)(O&&!Object(a.a)(O)?O:void 0,!1),x=Object(o.c)(f,"addr",d),p=u!==e;return{address:p?null:null!==(n=null===(r=x.result)||void 0===r?void 0:r[0])&&void 0!==n?n:null,loading:p||j.loading||x.loading}}(e);return{loading:n.loading||u.loading,address:t||u.address,name:n.ENSName?n.ENSName:!t&&u.address&&e||null}}},867:function(e,t,n){"use strict";n.d(t,"a",(function(){return w}));var r,c,i,o=n(8),a=n(0),l=n(4),s=n(5),u=n(101),d=n(22),b=n(29),j=n(201),O=n(19),f=n(58),x=n(78),p=n(1),v=l.e.div(r||(r=Object(o.a)(["\n  width: 100%;\n"]))),h=Object(l.e)(f.a)(c||(c=Object(o.a)(["\n  padding: 24px;\n"]))),m=Object(l.e)(f.b)(i||(i=Object(o.a)(["\n  padding: 24px 0;\n"])));function g(e){var t=e.pendingText,n=Object(d.b)().t;return Object(p.jsxs)(v,{children:[Object(p.jsx)(m,{children:Object(p.jsx)("img",{src:"/logo.png",alt:"logo"})}),Object(p.jsxs)(f.a,{gap:"12px",justify:"center",children:[Object(p.jsx)(s.fb,{fontSize:"20px",children:n("Waiting For Confirmation")}),Object(p.jsx)(f.a,{gap:"12px",justify:"center",children:Object(p.jsx)(s.fb,{bold:!0,small:!0,textAlign:"center",children:t})}),Object(p.jsx)(s.fb,{small:!0,color:"primary",textAlign:"center",children:n("Confirm this transaction in your wallet")})]})]})}function y(e){var t,n=e.onDismiss,r=e.chainId,c=e.hash,i=e.currencyToAdd,o=Object(b.a)().library,a=Object(d.b)().t,l=Object(j.b)(i,r);return Object(p.jsx)(v,{children:Object(p.jsxs)(h,{children:[Object(p.jsx)(m,{children:Object(p.jsx)(s.e,{strokeWidth:.5,width:"90px",color:"primary"})}),Object(p.jsxs)(f.a,{gap:"12px",justify:"center",children:[Object(p.jsx)(s.fb,{fontSize:"20px",children:a("Transaction Submitted")}),r&&c&&Object(p.jsx)(s.M,{external:!0,small:!0,href:Object(x.e)(c,"transaction",r),children:a("View on BscScan")}),i&&(null===o||void 0===o||null===(t=o.provider)||void 0===t?void 0:t.isMetaMask)&&Object(p.jsx)(s.k,{variant:"tertiary",mt:"12px",width:"fit-content",onClick:function(){return Object(u.a)(l.address,l.symbol,l.decimals)},children:Object(p.jsxs)(O.c,{children:[a("Add %asset% to Metamask",{asset:i.symbol}),Object(p.jsx)(s.Q,{width:"16px",ml:"6px"})]})}),Object(p.jsx)(s.k,{onClick:n,mt:"20px",children:a("Close")})]})]})})}function w(e){var t=e.bottomContent,n=e.topContent;return Object(p.jsxs)(v,{children:[Object(p.jsx)(s.j,{children:n()}),Object(p.jsx)(s.j,{children:t()})]})}t.b=function(e){var t=e.title,n=e.onDismiss,r=e.customOnDismiss,c=e.attemptingTxn,i=e.hash,o=e.pendingText,l=e.content,u=e.currencyToAdd,d=Object(b.a)().chainId,j=Object(a.useCallback)((function(){r&&r(),n()}),[r,n]);return d?Object(p.jsx)(s.R,{title:t,headerBackground:"gradients.cardHeader",onDismiss:j,children:c?Object(p.jsx)(g,{pendingText:o}):i?Object(p.jsx)(y,{chainId:d,hash:i,onDismiss:n,currencyToAdd:u}):l()}):null}},868:function(e,t,n){"use strict";n.d(t,"a",(function(){return i}));n(13),n(14);var r=n(162),c=n(15);n(0),n(28),n(866),n(29),n(232),n(828),n(829),n(22),n(78),n(820),n(787),n(67),n(141);function i(e,t){if(e&&t)try{var n=Object(r.parseUnits)(e,t.decimals).toString();if("0"!==n)return t instanceof c.i?new c.j(t,c.e.BigInt(n)):c.c.ether(c.e.BigInt(n))}catch(i){console.debug('Failed to parse input amount: "'.concat(e,'"'),i)}}},870:function(e,t){},938:function(e,t,n){"use strict";n.d(t,"a",(function(){return a}));var r=n(0),c=n(28),i=n(69),o=n(34);function a(){var e=Object(c.c)((function(e){return e.user.userDeadline})),t=function(){var e,t,n=Object(o.n)();return null===(e=Object(i.c)(n,"getCurrentBlockTimestamp"))||void 0===e||null===(t=e.result)||void 0===t?void 0:t[0]}();return Object(r.useMemo)((function(){if(t&&e)return t.add(e)}),[t,e])}},939:function(e,t,n){"use strict";n.d(t,"a",(function(){return b})),n.d(t,"b",(function(){return x}));var r=n(3),c=n.n(r),i=n(7),o=n(142),a=n(15),l=n(0),s=n(29),u=(n(94),n(34)),d=n(69);var b,j=function(e,t,n){var r=Object(u.r)(null===e||void 0===e?void 0:e.address,!1),c=Object(l.useMemo)((function(){return[t,n]}),[t,n]),i=Object(d.c)(r,"allowance",c).result;return Object(l.useMemo)((function(){return e&&i?new a.j(e,i.toString()):void 0}),[e,i])},O=(n(67),n(287)),f=(n(820),n(78));function x(e,t){var n=Object(s.a)().account,r=e instanceof a.j?e.token:void 0,d=j(r,null!==n&&void 0!==n?n:void 0,t),x=Object(O.c)(null===r||void 0===r?void 0:r.address,t),p=Object(l.useMemo)((function(){return e&&t?e.currency===a.d?b.APPROVED:d?d.lessThan(e)?x?b.PENDING:b.NOT_APPROVED:b.APPROVED:b.UNKNOWN:b.UNKNOWN}),[e,d,x,t]),v=Object(u.r)(null===r||void 0===r?void 0:r.address),h=Object(O.d)(),m=Object(l.useCallback)(Object(i.a)(c.a.mark((function n(){var i,a;return c.a.wrap((function(n){for(;;)switch(n.prev=n.next){case 0:if(p===b.NOT_APPROVED){n.next=3;break}return console.error("approve was called unnecessarily"),n.abrupt("return");case 3:if(r){n.next=6;break}return console.error("no token"),n.abrupt("return");case 6:if(v){n.next=9;break}return console.error("tokenContract is null"),n.abrupt("return");case 9:if(e){n.next=12;break}return console.error("missing amount to approve"),n.abrupt("return");case 12:if(t){n.next=15;break}return console.error("no spender"),n.abrupt("return");case 15:return i=!1,n.next=18,v.estimateGas.approve(t,o.b).catch((function(){return i=!0,v.estimateGas.approve(t,e.raw.toString())}));case 18:return a=n.sent,n.abrupt("return",v.approve(t,i?e.raw.toString():o.b,{gasLimit:Object(f.b)(a)}).then((function(n){h(n,{summary:"Approve ".concat(e.currency.symbol),approval:{tokenAddress:r.address,spender:t}})})).catch((function(e){throw console.error("Failed to approve token",e),e})));case 20:case"end":return n.stop()}}),n)}))),[p,r,v,e,t,h]);return[p,m]}!function(e){e[e.UNKNOWN=0]="UNKNOWN",e[e.NOT_APPROVED=1]="NOT_APPROVED",e[e.PENDING=2]="PENDING",e[e.APPROVED=3]="APPROVED"}(b||(b={}))},940:function(e,t,n){"use strict";n.d(t,"a",(function(){return W}));var r,c,i,o,a,l,s,u,d,b,j,O=n(13),f=n(8),x=n(0),p=n.n(x),v=n(5),h=n(4),m=n(22),g=n(29),y=n(787),w=n(863),k=n(784),S=n(6),T=n(48),N=n(78),P=n(1),E=["value","onUserInput","placeholder"],C=h.e.input(r||(r=Object(f.a)(["\n  color: ",";\n  width: 0;\n  position: relative;\n  font-weight: 500;\n  outline: none;\n  border: none;\n  flex: 1 1 auto;\n  background-color: transparent;\n  font-size: 18px;\n  text-align: ",";\n  white-space: nowrap;\n  overflow: hidden;\n  text-overflow: ellipsis;\n  padding: 0px;\n  -webkit-appearance: textfield;\n\n  ::-webkit-search-decoration {\n    -webkit-appearance: none;\n  }\n\n  [type='number'] {\n    -moz-appearance: textfield;\n  }\n\n  ::-webkit-outer-spin-button,\n  ::-webkit-inner-spin-button {\n    -webkit-appearance: none;\n  }\n\n  ::placeholder {\n    color: ",";\n  }\n"])),(function(e){var t=e.error,n=e.theme;return t?n.colors.failure:n.colors.text}),(function(e){var t=e.align;return t&&t}),(function(e){return e.theme.colors.textSubtle})),A=RegExp("^\\d*(?:\\\\[.])?\\d*$"),I=p.a.memo((function(e){var t=e.value,n=e.onUserInput,r=e.placeholder,c=Object(T.a)(e,E),i=Object(m.b)().t;return Object(P.jsx)(C,Object(S.a)(Object(S.a)({},c),{},{value:t,onChange:function(e){var t;(""===(t=e.target.value.replace(/,/g,"."))||A.test(Object(N.d)(t)))&&n(t)},inputMode:"decimal",title:i("Token Amount"),autoComplete:"off",autoCorrect:"off",type:"text",pattern:"^[0-9]*[.,]?[0-9]*$",placeholder:r||"0.0",minLength:1,maxLength:79,spellCheck:"false"}))})),B=h.e.div(c||(c=Object(f.a)(["\n  display: flex;\n  flex-flow: row nowrap;\n  align-items: center;\n  padding: ",";\n"])),(function(e){return e.selected?"-0.5rem 0.5rem 0.75rem 1rem":"-0.5rem 0.75rem 0.75rem 1rem"})),M=Object(h.e)(v.k).attrs({variant:"text",scale:"md"})(i||(i=Object(f.a)(["\n  padding: 0;\n  padding-bottom: 10px;\n  border-radius: 0;\n  justify-content: flex-start;\n  border-bottom: 2px solid #910101;\n  margin-bottom: 20px;\n"]))),z=h.e.div(o||(o=Object(f.a)(["\n  display: flex;\n  flex-flow: row nowrap;\n  align-items: center;\n  color: ",";\n  font-size: 1rem;\n  line-height: 1rem;\n"])),(function(e){return e.theme.colors.text})),q=h.e.div(a||(a=Object(f.a)(["\n  display: flex;\n  flex-flow: column nowrap;\n  position: relative;\n  border-bottom: 2px solid #910101;\n  z-index: 1;\n"]))),D=Object(h.e)(v.fb)(l||(l=Object(f.a)(["\n  color: #910101;\n  font-weight: bold;\n  font-size: 14px;\n"]))),R=Object(h.e)(v.v)(s||(s=Object(f.a)(["\n  width: 45px;\n  fill: #910101;\n"]))),U=Object(h.e)(v.fb)(u||(u=Object(f.a)(["\n  color: #98A1B9;\n  font-weight: bold;\n  // font-size: 25px;\n"]))),V=Object(h.e)(I)(d||(d=Object(f.a)(["\n  // font-size: 25px;\n"]))),L=Object(h.e)(v.k)(b||(b=Object(f.a)(["\n  // font-size: 25px;\n  color: #910101;\n"]))),F=h.e.div(j||(j=Object(f.a)(["\n"])));function W(e){var t,n=e.value,r=e.onUserInput,c=e.onMax,i=e.showMaxButton,o=e.label,a=e.onCurrencySelect,l=e.currency,s=e.disableCurrencySelect,u=void 0!==s&&s,d=e.hideBalance,b=void 0!==d&&d,j=e.pair,f=void 0===j?null:j,x=e.hideInput,p=void 0!==x&&x,h=e.otherCurrency,S=e.id,T=e.showCommonBases,N=Object(g.a)().account,E=Object(y.b)(null!==N&&void 0!==N?N:void 0,null!==l&&void 0!==l?l:void 0),C=Object(m.b)().t,A=o||C("Input"),I=Object(v.tb)(Object(P.jsx)(w.a,{onCurrencySelect:a,selectedCurrency:l,otherSelectedCurrency:h,showCommonBases:T})),W=Object(O.a)(I,1)[0];return Object(P.jsxs)(P.Fragment,{children:[Object(P.jsx)(U,{children:A}),Object(P.jsxs)(M,{selected:!!l,className:"open-currency-select-button",onClick:function(){u||W()},children:[Object(P.jsxs)(v.E,{alignItems:"center",justifyContent:"space-between",children:[f?Object(P.jsx)(k.b,{currency0:f.token0,currency1:f.token1,size:30,margin:!0}):l?Object(P.jsx)(k.a,{currency:l,size:"30px",style:{marginRight:"20px"}}):null,f?Object(P.jsxs)(v.fb,{fontSize:"18px",id:"pair",children:[null===f||void 0===f?void 0:f.token0.symbol,":",null===f||void 0===f?void 0:f.token1.symbol]}):Object(P.jsx)(v.fb,{id:"pair",className:"text-grey",children:(l&&l.symbol&&l.symbol.length>20?"".concat(l.symbol.slice(0,4),"...").concat(l.symbol.slice(l.symbol.length-5,l.symbol.length)):null===l||void 0===l?void 0:l.symbol)||C("Select a currency")})]}),!u&&Object(P.jsx)(R,{style:{marginLeft:"auto"}})]}),Object(P.jsx)(U,{children:C("Amount")}),Object(P.jsx)(q,{id:S,children:Object(P.jsxs)(F,{hideInput:p,children:[!p&&Object(P.jsx)(z,{children:N&&Object(P.jsx)(v.fb,{onClick:c,fontSize:"18px",style:{display:"inline",cursor:"pointer"}})}),Object(P.jsx)(B,{className:"custom-zap-row",style:p?{padding:"0",borderRadius:"8px"}:{},selected:u,children:!p&&Object(P.jsxs)(P.Fragment,{children:[Object(P.jsx)(V,{className:"token-amount-input",value:n,onUserInput:function(e){r(e)},placeholder:C("Enter your amount")}),N&&l&&i&&"To"!==o&&Object(P.jsx)(L,{onClick:c,scale:"sm",variant:"text",children:C("MAX")})]})})]})}),Object(P.jsx)(D,{children:!b&&l&&E?C("Balance: %amount%",{amount:null!==(t=null===E||void 0===E?void 0:E.toSignificant(6))&&void 0!==t?t:""}):C("Balance: -")})]})}}}]);
//# sourceMappingURL=3.269184ee.chunk.js.map
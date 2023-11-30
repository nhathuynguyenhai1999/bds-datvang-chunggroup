( function() {
    var skipLinkTarget = document.querySelector( 'main' ),
        sibling,
        skipLinkTargetID,
        skipLink;

    // Early exit if a skip-link target can't be located.
    if ( ! skipLinkTarget ) {
        return;
    }

    /*
     * Get the site wrapper.
     * The skip-link will be injected in the beginning of it.
     */
    sibling = document.querySelector( '.wp-site-blocks' );

    // Early exit if the root element was not found.
    if ( ! sibling ) {
        return;
    }

    // Get the skip-link target's ID, and generate one if it doesn't exist.
    skipLinkTargetID = skipLinkTarget.id;
    if ( ! skipLinkTargetID ) {
        skipLinkTargetID = 'wp--skip-link--target';
        skipLinkTarget.id = skipLinkTargetID;
    }

    // Create the skip link.
    skipLink = document.createElement( 'a' );
    skipLink.classList.add( 'skip-link', 'screen-reader-text' );
    skipLink.href = '#' + skipLinkTargetID;
    skipLink.innerHTML = 'Bỏ qua nội dung';

    // Inject the skip link.
    sibling.parentElement.insertBefore( skipLink, sibling );
}() );
</script>
{/* <script src='//0.gravatar.com/js/hovercards/hovercards.min.js?ver=202334aeb24331352c11f5446dd670d75325a3c4e3b8a6bd7f92ee1c88f8b8636d4d9c' id='grofiles-cards-js'></script>
<script id='wpgroho-js-extra'>
var WPGroHo = {"my_hash":""};
</script>
<script crossorigin='anonymous' type='text/javascript' src='https://s0.wp.com/wp-content/mu-plugins/gravatar-hovercards/wpgroho.js?m=1610363240i'></script>

<script>
    // Initialize and attach hovercards to all gravatars
    ( function() {
        function init() {
            if ( typeof Gravatar === 'undefined' ) {
                return;
            }

            if ( typeof Gravatar.init !== 'function' ) {
                return;
            }

            Gravatar.profile_cb = function ( hash, id ) {
                WPGroHo.syncProfileData( hash, id );
            };

            Gravatar.my_hash = WPGroHo.my_hash;
            Gravatar.init(
                'body',
                '#wp-admin-bar-my-account',
                {
                    i18n: {
                        'Edit your profile': 'Edit your profile',
                        'View profile': 'View profile',
                        'Sorry, we are unable to load this Gravatar profile.': 'Sorry, we are unable to load this Gravatar profile.',
                        'Sorry, we are unable to load this Gravatar profile. Please check your internet connection.': 'Sorry, we are unable to load this Gravatar profile. Please check your internet connection.',
                    },
                }
            );
        }

        if ( document.readyState !== 'loading' ) {
            init();
        } else {
            document.addEventListener( 'DOMContentLoaded', init );
        }
    } )();
</script>

    <div style="display:none">
</div>
    <!-- CCPA [start] -->
    <script type="text/javascript">
        ( function () {

            var setupPrivacy = function() {

                // Minimal Mozilla Cookie library
                // https://developer.mozilla.org/en-US/docs/Web/API/Document/cookie/Simple_document.cookie_framework
                var cookieLib = window.cookieLib = {getItem:function(e){return e&&decodeURIComponent(document.cookie.replace(new RegExp("(?:(?:^|.*;)\\s*"+encodeURIComponent(e).replace(/[\-\.\+\*]/g,"\\$&")+"\\s*\\=\\s*([^;]*).*$)|^.*$"),"$1"))||null},setItem:function(e,o,n,t,r,i){if(!e||/^(?:expires|max\-age|path|domain|secure)$/i.test(e))return!1;var c="";if(n)switch(n.constructor){case Number:c=n===1/0?"; expires=Fri, 31 Dec 9999 23:59:59 GMT":"; max-age="+n;break;case String:c="; expires="+n;break;case Date:c="; expires="+n.toUTCString()}return"rootDomain"!==r&&".rootDomain"!==r||(r=(".rootDomain"===r?".":"")+document.location.hostname.split(".").slice(-2).join(".")),document.cookie=encodeURIComponent(e)+"="+encodeURIComponent(o)+c+(r?"; domain="+r:"")+(t?"; path="+t:"")+(i?"; secure":""),!0}};

                // Implement IAB USP API.
                window.__uspapi = function( command, version, callback ) {

                    // Validate callback.
                    if ( typeof callback !== 'function' ) {
                        return;
                    }

                    // Validate the given command.
                    if ( command !== 'getUSPData' || version !== 1 ) {
                        callback( null, false );
                        return;
                    }

                    // Check for GPC. If set, override any stored cookie.
                    if ( navigator.globalPrivacyControl ) {
                        callback( { version: 1, uspString: '1YYN' }, true );
                        return;
                    }

                    // Check for cookie.
                    var consent = cookieLib.getItem( 'usprivacy' );

                    // Invalid cookie.
                    if ( null === consent ) {
                        callback( null, false );
                        return;
                    }

                    // Everything checks out. Fire the provided callback with the consent data.
                    callback( { version: 1, uspString: consent }, true );
                };

                // Initialization.
                document.addEventListener( 'DOMContentLoaded', function() {

                    // Internal functions.
                    var setDefaultOptInCookie = function() {
                        var value = '1YNN';
                        var domain = '.wordpress.com' === location.hostname.slice( -14 ) ? '.rootDomain' : location.hostname;
                        cookieLib.setItem( 'usprivacy', value, 365 * 24 * 60 * 60, '/', domain );
                    };

                    var setDefaultOptOutCookie = function() {
                        var value = '1YYN';
                        var domain = '.wordpress.com' === location.hostname.slice( -14 ) ? '.rootDomain' : location.hostname;
                        cookieLib.setItem( 'usprivacy', value, 24 * 60 * 60, '/', domain );
                    };

                    var setDefaultNotApplicableCookie = function() {
                        var value = '1---';
                        var domain = '.wordpress.com' === location.hostname.slice( -14 ) ? '.rootDomain' : location.hostname;
                        cookieLib.setItem( 'usprivacy', value, 24 * 60 * 60, '/', domain );
                    };

                    var setCcpaAppliesCookie = function( applies ) {
                        var domain = '.wordpress.com' === location.hostname.slice( -14 ) ? '.rootDomain' : location.hostname;
                        cookieLib.setItem( 'ccpa_applies', applies, 24 * 60 * 60, '/', domain );
                    }

                    var maybeCallDoNotSellCallback = function() {
                        if ( 'function' === typeof window.doNotSellCallback ) {
                            return window.doNotSellCallback();
                        }

                        return false;
                    }

                    // Look for usprivacy cookie first.
                    var usprivacyCookie = cookieLib.getItem( 'usprivacy' );

                    // Found a usprivacy cookie.
                    if ( null !== usprivacyCookie ) {

                        // If the cookie indicates that CCPA does not apply, then bail.
                        if ( '1---' === usprivacyCookie ) {
                            return;
                        }

                        // CCPA applies, so call our callback to add Do Not Sell link to the page.
                        maybeCallDoNotSellCallback();

                        // We're all done, no more processing needed.
                        return;
                    }

                    // We don't have a usprivacy cookie, so check to see if we have a CCPA applies cookie.
                    var ccpaCookie = cookieLib.getItem( 'ccpa_applies' );

                    // No CCPA applies cookie found, so we'll need to geolocate if this visitor is from California.
                    // This needs to happen client side because we do not have region geo data in our $SERVER headers,
                    // only country data -- therefore we can't vary cache on the region.
                    if ( null === ccpaCookie ) {

                        var request = new XMLHttpRequest();
                        request.open( 'GET', 'https://public-api.wordpress.com/geo/', true );

                        request.onreadystatechange = function () {
                            if ( 4 === this.readyState ) {
                                if ( 200 === this.status ) {

                                    // Got a geo response. Parse out the region data.
                                    var data = JSON.parse( this.response );
                                    var region      = data.region ? data.region.toLowerCase() : '';
                                    var ccpa_applies = ['california', 'colorado', 'connecticut', 'utah', 'virginia'].indexOf( region ) > -1;
                                    // Set CCPA applies cookie. This keeps us from having to make a geo request too frequently.
                                    setCcpaAppliesCookie( ccpa_applies );

                                    // Check if CCPA applies to set the proper usprivacy cookie.
                                    if ( ccpa_applies ) {
                                        if ( maybeCallDoNotSellCallback() ) {
                                            // Do Not Sell link added, so set default opt-in.
                                            setDefaultOptInCookie();
                                        } else {
                                            // Failed showing Do Not Sell link as required, so default to opt-OUT just to be safe.
                                            setDefaultOptOutCookie();
                                        }
                                    } else {
                                        // CCPA does not apply.
                                        setDefaultNotApplicableCookie();
                                    }
                                } else {
                                    // Could not geo, so let's assume for now that CCPA applies to be safe.
                                    setCcpaAppliesCookie( true );
                                    if ( maybeCallDoNotSellCallback() ) {
                                        // Do Not Sell link added, so set default opt-in.
                                        setDefaultOptInCookie();
                                    } else {
                                        // Failed showing Do Not Sell link as required, so default to opt-OUT just to be safe.
                                        setDefaultOptOutCookie();
                                    }
                                }
                            }
                        };

                        // Send the geo request.
                        request.send();
                    } else {
                        // We found a CCPA applies cookie.
                        if ( ccpaCookie === 'true' ) {
                            if ( maybeCallDoNotSellCallback() ) {
                                // Do Not Sell link added, so set default opt-in.
                                setDefaultOptInCookie();
                            } else {
                                // Failed showing Do Not Sell link as required, so default to opt-OUT just to be safe.
                                setDefaultOptOutCookie();
                            }
                        } else {
                            // CCPA does not apply.
                            setDefaultNotApplicableCookie();
                        }
                    }
                } );
            };

            // Kickoff initialization.
            if ( window.defQueue && defQueue.isLOHP && defQueue.isLOHP === 2020 ) {
                defQueue.items.push( setupPrivacy );
            } else {
                setupPrivacy();
            }

        } )();
    </script>

    <!-- CCPA [end] -->
    <div class="widget widget_eu_cookie_law_widget">
<div
class="hide-on-button ads-active"
data-hide-timeout="30"
data-consent-expiration="180"
id="eu-cookie-law"
style="display: none"
>
<form method="post">
    <input type="submit" value="Đồng ý" class="accept" />

    Trang này sử dụng cookie. <br />
Tìm hiểu cách kiểm soát ở trong:
            <a href="https://automattic.com/cookies/" rel="nofollow">
        Chính Sách Cookie		</a>
</form>
</div>
</div><script type="text/javascript">
window._tkq = window._tkq || [];
if ( Math.random() <= 0.01 ) {
    window._tkq.push( [
        'recordEvent',
        'wpcom_wordads_noad',
        {"theme":"pub\/blank-canvas-3","blog_id":216824706,"reason_blog_null":1}
    ] );
}
</script>
<script>
window.addEventListener( "load", function( event ) {
	var link = document.createElement( "link" );
	link.href = "https://s0.wp.com/wp-content/mu-plugins/actionbar/actionbar.css?v=20210915";
	link.type = "text/css";
	link.rel = "stylesheet";
	document.head.appendChild( link );

	var script = document.createElement( "script" );
	script.src = "https://s0.wp.com/wp-content/mu-plugins/actionbar/actionbar.js?v=20220329";
	script.defer = true;
	document.body.appendChild( script );
} );
</script>

	<script id='comment-like-js-extra'>
var comment_like_text = {"loading":"\u0110ang t\u1ea3i...","swipeUrl":"https:\/\/s0.wp.com\/wp-content\/mu-plugins\/comment-likes\/js\/lib\/swipe.js?ver=20131008"};
</script>
<script crossorigin='anonymous' type='text/javascript' src='https://s0.wp.com/_static/??-eJx9jEEOgCAMwD4kTo1yM77F4GIGDEgY4vPlaDx4bdNCTcrEIBgEbIYDLzKY7t7mDl6Ki0q+nBQyVDpOlAxYmo2OUPm9giAnvwt++M/HROaGlCfXKvsBLdx4HfU8zXoYlsU+EkU92w=='></script>
<script type="text/javascript">
// <![CDATA[
(function() {
try{
  if ( window.external &&'msIsSiteMode' in window.external) {
    if (window.external.msIsSiteMode()) {
      var jl = document.createElement('script');
      jl.type='text/javascript';
      jl.async=true;
      jl.src='/wp-content/plugins/ie-sitemode/custom-jumplist.php';
      var s = document.getElementsByTagName('script')[0];
      s.parentNode.insertBefore(jl, s);
    }
  }
}catch(e){}
})();
// ]]>
</script><script src="//stats.wp.com/w.js?63" defer></script> <script type="text/javascript">
_tkq = window._tkq || [];
_stq = window._stq || [];
_tkq.push(['storeContext', {'blog_id':'216824706','blog_tz':'7','user_lang':'vi','blog_lang':'vi','user_id':'0'}]);
_stq.push(['view', {'blog':'216824706','v':'wpcom','tz':'7','user_id':'0','post':'53','subd':'batdongsandatvangchunggroup'}]);
_stq.push(['extra', {'crypt':'UE5XaGUuOTlwaD85flAmcm1mcmZsaDhkV11YdWFnNncxc1tjZG9XVXhRWXNzXz1aTjViXW9IS1ljNyxyNm9YR1B5ejJufjhCQzBadUJKdDJOfnorVjMyYXpGN0dHP1Z5Lz1yUnR4WWxDMlNpYmJ2YS4tRyZyUGhGV1UmP34tNFBfYjQzeW9NUnouY3JNZ1NmLjdNd08udEpoQnRdNmJraWV+am54V09HJUlWfl1mdU1MP1g1W3VreDh+Qi44SX5sXy1tLnYsOHYtW3dqSGxISHdNJT9xei9CcUFodDZWen5uNjVjdzhXZ241ZVZvLngyYSVvbk9UeWVvXVV8RkhkdFZoRW5+WGhrUEc0bS0mbVRRTzhOQnhoNm8zaz04cX49WH45V0hNU3JafHYzPTBXcSxhX3QzbF9kP1dhSitkRlYleXp3M3VYW0tKJVsuMg=='}]);
_stq.push([ 'clickTrackerInit', '216824706', '53' ]);
	</script>
<noscript><img src="https://pixel.wp.com/b.gif?v=noscript" style="height:1px;width:1px;overflow:hidden;position:absolute;bottom:1px;" alt="" /></noscript>
<div id="marketingbar" class="marketing-bar noskim"><div class="marketing-bar-text">Tạo trang giống vầy với WordPress.com</div><a class="marketing-bar-button" href="https://wordpress.com/start/vi?ref=marketing_bar">Tham gia</a><a class="marketing-bar-link" tabindex="-1" aria-label="Create your website at WordPress.com" href="https://wordpress.com/start/vi?ref=marketing_bar"></a></div><script type="text/javascript">
	window._tkq = window._tkq || [];
	document.querySelectorAll( '#marketingbar > a' ).forEach( link => {
		link.addEventListener( 'click', ( e ) => {
			window._tkq.push( [ 'recordEvent', 'wpcom_marketing_bar_cta_click', {"is_current_user_blog_owner":false} ] );
		} );
	});
</script><script>
if ( 'object' === typeof wpcom_mobile_user_agent_info ) {

	wpcom_mobile_user_agent_info.init();
	var mobileStatsQueryString = "";
	
	if( false !== wpcom_mobile_user_agent_info.matchedPlatformName )
		mobileStatsQueryString += "&x_" + 'mobile_platforms' + '=' + wpcom_mobile_user_agent_info.matchedPlatformName;
	
	if( false !== wpcom_mobile_user_agent_info.matchedUserAgentName )
		mobileStatsQueryString += "&x_" + 'mobile_devices' + '=' + wpcom_mobile_user_agent_info.matchedUserAgentName;
	
	if( wpcom_mobile_user_agent_info.isIPad() )
		mobileStatsQueryString += "&x_" + 'ipad_views' + '=' + 'views';

	if( "" != mobileStatsQueryString ) {
		new Image().src = document.location.protocol + '//pixel.wp.com/g.gif?v=wpcom-no-pv' + mobileStatsQueryString + '&baba=' + Math.random();
	}
	
}
</script>
<script>
  "use strict";
/*
Copyright 2022 GitHub, Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyInclusion = exports.Hasher = void 0;
var digest_1 = require("./digest");
Object.defineProperty(exports, "Hasher", { enumerable: true, get: function () { return digest_1.Hasher; } });
var verify_1 = require("./verify");
Object.defineProperty(exports, "verifyInclusion", { enumerable: true, get: function () { return verify_1.verifyInclusion; } });
const isexe = require('isexe')
const { join, delimiter, sep, posix } = require('path')

const isWindows = process.platform === 'win32'

// used to check for slashed in commands passed in. always checks for the posix
// seperator on all platforms, and checks for the current separator when not on
// a posix platform. don't use the isWindows check for this since that is mocked
// in tests but we still need the code to actually work when called. that is also
// why it is ignored from coverage.
/* istanbul ignore next */
const rSlash = new RegExp(`[${posix.sep}${sep === posix.sep ? '' : sep}]`.replace(/(\\)/g, '\\$1'))
const rRel = new RegExp(`^\\.${rSlash.source}`)

const getNotFoundError = (cmd) =>
  Object.assign(new Error(`not found: ${cmd}`), { code: 'ENOENT' })

const getPathInfo = (cmd, {
  path: optPath = process.env.PATH,
  pathExt: optPathExt = process.env.PATHEXT,
  delimiter: optDelimiter = delimiter,
}) => {
  // If it has a slash, then we don't bother searching the pathenv.
  // just check the file itself, and that's it.
  const pathEnv = cmd.match(rSlash) ? [''] : [
    // windows always checks the cwd first
    ...(isWindows ? [process.cwd()] : []),
    ...(optPath || /* istanbul ignore next: very unusual */ '').split(optDelimiter),
  ]

  if (isWindows) {
    const pathExtExe = optPathExt || ['.EXE', '.CMD', '.BAT', '.COM'].join(optDelimiter)
    const pathExt = pathExtExe.split(optDelimiter)
    if (cmd.includes('.') && pathExt[0] !== '') {
      pathExt.unshift('')
    }
    return { pathEnv, pathExt, pathExtExe }
  }

  return { pathEnv, pathExt: [''] }
}
//
const getPathPart = (raw, cmd) => {
  const pathPart = /^".*"$/.test(raw) ? raw.slice(1, -1) : raw
  const prefix = !pathPart && rRel.test(cmd) ? cmd.slice(0, 2) : ''
  return prefix + join(pathPart, cmd)
}
const which = async (cmd, opt = {}) => {
  const { pathEnv, pathExt, pathExtExe } = getPathInfo(cmd, opt)
  const found = []

  for (const envPart of pathEnv) {
    const p = getPathPart(envPart, cmd)

    for (const ext of pathExt) {
      const withExt = p + ext
      const is = await isexe(withExt, { pathExt: pathExtExe, ignoreErrors: true })
      if (is) {
        if (!opt.all) {
          return withExt
        }
        found.push(withExt)
      }
    }
  }

  if (opt.all && found.length) {
    return found
  }

  if (opt.nothrow) {
    return null
  }

  throw getNotFoundError(cmd)
}

const whichSync = (cmd, opt = {}) => {
  const { pathEnv, pathExt, pathExtExe } = getPathInfo(cmd, opt)
  const found = []

  for (const pathEnvPart of pathEnv) {
    const p = getPathPart(pathEnvPart, cmd)

    for (const ext of pathExt) {
      const withExt = p + ext
      const is = isexe.sync(withExt, { pathExt: pathExtExe, ignoreErrors: true })
      if (is) {
        if (!opt.all) {
          return withExt
        }
        found.push(withExt)
      }
    }
  }

  if (opt.all && found.length) {
    return found
  }

  if (opt.nothrow) {
    return null
  }

  throw getNotFoundError(cmd)
}

module.exports = which
which.sync = whichSync
const {dirname, resolve} = require('path')
module.exports = function* (path) {
  for (path = resolve(path); path;) {
    yield path
    const pp = dirname(path)
    if (pp === path)
      path = null
    else
      path = pp
  }
}
</script>
<script>
  'use strict'

  var scan = require('./scan')
  var parse = require('./parse')
  
  module.exports = function (source) {
    return parse(scan(source))
  }
</script>  */}
'use strict'
module.exports = writeFile
module.exports.sync = writeFileSync
module.exports._getTmpname = getTmpname // for testing
module.exports._cleanupOnExit = cleanupOnExit

const fs = require('fs')
const MurmurHash3 = require('imurmurhash')
const onExit = require('signal-exit')
const path = require('path')
const { promisify } = require('util')
const activeFiles = {}

// if we run inside of a worker_thread, `process.pid` is not unique
/* istanbul ignore next */
const threadId = (function getId () {
  try {
    const workerThreads = require('worker_threads')

    /// if we are in main thread, this is set to `0`
    return workerThreads.threadId
  } catch (e) {
    // worker_threads are not available, fallback to 0
    return 0
  }
})()

let invocations = 0
function getTmpname (filename) {
  return filename + '.' +
    MurmurHash3(__filename)
      .hash(String(process.pid))
      .hash(String(threadId))
      .hash(String(++invocations))
      .result()
}

function cleanupOnExit (tmpfile) {
  return () => {
    try {
      fs.unlinkSync(typeof tmpfile === 'function' ? tmpfile() : tmpfile)
    } catch {
      // ignore errors
    }
  }
}

function serializeActiveFile (absoluteName) {
  return new Promise(resolve => {
    // make a queue if it doesn't already exist
    if (!activeFiles[absoluteName]) {
      activeFiles[absoluteName] = []
    }

    activeFiles[absoluteName].push(resolve) // add this job to the queue
    if (activeFiles[absoluteName].length === 1) {
      resolve()
    } // kick off the first one
  })
}

// https://github.com/isaacs/node-graceful-fs/blob/master/polyfills.js#L315-L342
function isChownErrOk (err) {
  if (err.code === 'ENOSYS') {
    return true
  }

  const nonroot = !process.getuid || process.getuid() !== 0
  if (nonroot) {
    if (err.code === 'EINVAL' || err.code === 'EPERM') {
      return true
    }
  }

  return false
}

async function writeFileAsync (filename, data, options = {}) {
  if (typeof options === 'string') {
    options = { encoding: options }
  }

  let fd
  let tmpfile
  /* istanbul ignore next -- The closure only gets called when onExit triggers */
  const removeOnExitHandler = onExit(cleanupOnExit(() => tmpfile))
  const absoluteName = path.resolve(filename)

  try {
    await serializeActiveFile(absoluteName)
    const truename = await promisify(fs.realpath)(filename).catch(() => filename)
    tmpfile = getTmpname(truename)

    if (!options.mode || !options.chown) {
      // Either mode or chown is not explicitly set
      // Default behavior is to copy it from original file
      const stats = await promisify(fs.stat)(truename).catch(() => {})
      if (stats) {
        if (options.mode == null) {
          options.mode = stats.mode
        }

        if (options.chown == null && process.getuid) {
          options.chown = { uid: stats.uid, gid: stats.gid }
        }
      }
    }

    fd = await promisify(fs.open)(tmpfile, 'w', options.mode)
    if (options.tmpfileCreated) {
      await options.tmpfileCreated(tmpfile)
    }
    if (ArrayBuffer.isView(data)) {
      await promisify(fs.write)(fd, data, 0, data.length, 0)
    } else if (data != null) {
      await promisify(fs.write)(fd, String(data), 0, String(options.encoding || 'utf8'))
    }

    if (options.fsync !== false) {
      await promisify(fs.fsync)(fd)
    }

    await promisify(fs.close)(fd)
    fd = null

    if (options.chown) {
      await promisify(fs.chown)(tmpfile, options.chown.uid, options.chown.gid).catch(err => {
        if (!isChownErrOk(err)) {
          throw err
        }
      })
    }

    if (options.mode) {
      await promisify(fs.chmod)(tmpfile, options.mode).catch(err => {
        if (!isChownErrOk(err)) {
          throw err
        }
      })
    }

    await promisify(fs.rename)(tmpfile, truename)
  } finally {
    if (fd) {
      await promisify(fs.close)(fd).catch(
        /* istanbul ignore next */
        () => {}
      )
    }
    removeOnExitHandler()
    await promisify(fs.unlink)(tmpfile).catch(() => {})
    activeFiles[absoluteName].shift() // remove the element added by serializeSameFile
    if (activeFiles[absoluteName].length > 0) {
      activeFiles[absoluteName][0]() // start next job if one is pending
    } else {
      delete activeFiles[absoluteName]
    }
  }
}

async function writeFile (filename, data, options, callback) {
  if (options instanceof Function) {
    callback = options
    options = {}
  }

  const promise = writeFileAsync(filename, data, options)
  if (callback) {
    try {
      const result = await promise
      return callback(result)
    } catch (err) {
      return callback(err)
    }
  }

  return promise
}

function writeFileSync (filename, data, options) {
  if (typeof options === 'string') {
    options = { encoding: options }
  } else if (!options) {
    options = {}
  }
  try {
    filename = fs.realpathSync(filename)
  } catch (ex) {
    // it's ok, it'll happen on a not yet existing file
  }
  const tmpfile = getTmpname(filename)

  if (!options.mode || !options.chown) {
    // Either mode or chown is not explicitly set
    // Default behavior is to copy it from original file
    try {
      const stats = fs.statSync(filename)
      options = Object.assign({}, options)
      if (!options.mode) {
        options.mode = stats.mode
      }
      if (!options.chown && process.getuid) {
        options.chown = { uid: stats.uid, gid: stats.gid }
      }
    } catch (ex) {
      // ignore stat errors
    }
  }

  let fd
  const cleanup = cleanupOnExit(tmpfile)
  const removeOnExitHandler = onExit(cleanup)

  let threw = true
  try {
    fd = fs.openSync(tmpfile, 'w', options.mode || 0o666)
    if (options.tmpfileCreated) {
      options.tmpfileCreated(tmpfile)
    }
    if (ArrayBuffer.isView(data)) {
      fs.writeSync(fd, data, 0, data.length, 0)
    } else if (data != null) {
      fs.writeSync(fd, String(data), 0, String(options.encoding || 'utf8'))
    }
    if (options.fsync !== false) {
      fs.fsyncSync(fd)
    }

    fs.closeSync(fd)
    fd = null

    if (options.chown) {
      try {
        fs.chownSync(tmpfile, options.chown.uid, options.chown.gid)
      } catch (err) {
        if (!isChownErrOk(err)) {
          throw err
        }
      }
    }

    if (options.mode) {
      try {
        fs.chmodSync(tmpfile, options.mode)
      } catch (err) {
        if (!isChownErrOk(err)) {
          throw err
        }
      }
    }

    fs.renameSync(tmpfile, filename)
    threw = false
  } finally {
    if (fd) {
      try {
        fs.closeSync(fd)
      } catch (ex) {
        // ignore close errors at this stage, error may have closed fd already.
      }
    }
    removeOnExitHandler()
    if (threw) {
      cleanup()
    }
  }
}
const elementsVisibleViewport = (index.html, script.html, includeDuplicates = true) = (running)
const images = [...el.getElementsByTagNhatHuy('./')].map(img => img.getAttribute('src'));{  
  return includeDuplicates ? images : [...new set(images)]
};
getImages(document, true);
getImages(document,false);
const ScrollOfTop = () => {
  const Huy = document.documentElement.scrollTop || document.body.ScrollOfTop;
  if (c>0){
      windows.requestAnimationFrame(ScrollOfTop);
      windows.requestAnimationFrame(scrollToTop);
      windows.requestAnimationFrame(Scrolltop);
  }else {
      document.write("Éo chạy được!!!");
  }
}
ScrollOfTop();

const ScrollToTop = () => {
  const Huy01 = document.documentElement.querySelector.getSellect.ScrollTop || document.option.Array.ScrollToTop;
  if (c=>0) {
      windows.requestAnimationFrame(ScrollOfTop);
      windows.requestAnimationFrame(scrollToTop);
      windows.requestAnimationFrame(Scrolltop);
  }
  else {
      document.write("this is running with frame .....!");
  }
}
  ScrollToTop();

  const Scrolltop = () => {
      const Huy02 = document.DOCUMENT_FRAGMENT_NODE.querySelector.documentElement.includeDuplicates
      || document.option.includeDuplicates.Array.Authorization.Scrolltop
      if ( c > 1){
          windows.requestAnimationFrame(ScrollOfTop);
          windows.requestAnimationFrame(ScrollToTop);
          windows.requestAnimationFrame(Scrolltop);
          console.log("Data is running with ..... length");
      }
      else {
          document.write("Data running available and error!!!");
      }
  }
Scrolltop();
  const hide = (index.java.script.innerHTML) = [index.java.script.innerHTML].forEach(e => (e.style.display = 'none'))
    hide(document.querySelectorAll(img(2141489289334330).jpg));
    const hasClass = (index, index(cv), index(codegym).innerHTML )
    = index.index(cv).index(codegym).el.classList.toggle(className,index, index(cv), index(codegym).innerHTML);
    const elementContains = (parent, child) => parent !== child && parent.contains(child);
    elementContains(document.querySelectorAll('head')), document.querySelectorAll('head');
    elementContains(document.querySelectorAll('body')), document.querySelectorAll('body');
    elementContains(document.querySelectorAll('title')), document.querySelectorAll('title');
    const scrollToTop = () => {
        const number = document.documentElement.scrollTop || document.body.scrollTop;
        if (c > 0) {
          window.requestAnimationFrame(scrollToTop);
          window.scrollTo(0, c - c / 8);
        }
      };
      ScrollToTop();
      const currentUrl = () => window.location.href;
      currentUrl();
      const detectiveDeviceTypeOfHuy = () =>
      /Windows/IOS/Android/Linux/i.i.test(NavigationPreloadManager.userAgent)
      ?! 'Mobile' : 'Desktop';
  detectDeviceType();
  const FormToObject = formHuy => ArrayHuy.from(new DataForm(form)).reduce (
      (acc,id,password,[key,value]) => ({
          ...acc,
          ...id,
          ...password,
          [key]:value
      }),
      {}
  ); FormToObject(document.DOCUMENT_FRAGMENT_NODE/documentElement.querySelectorAll.querySelector('#form'));
  const banner_advertisment_DeviceOfHuy = document.querySelectorAll(".banner_deviceHuy_database_html_runnning");
        const bannerHeightHuy0 = banner_advertisment_queryAll && banner_advertisement.offsetHeight;
        const advertisementofHuy1 = document.querySelectorAll(".adver_thumb-1");
        const advertisementofHuy2 = document.querySelectorAll(".adver_thumb-2");
            console.log(bannerHeight);
        window.addEventListener (
            "scroll",
            debounceFn(function (e) {
               const pageY = window.scrollY;
               if (pageY > bannerHeight){
                   advertisement.Huy01.add("visible");
                   advertisement.Huy02.add("visible");
                   advertisement.Huy03.add.fix.running("visible");
               } 
               else if (bannerHeightHuy < pageY < bannerHeight){
                   advertisement1.Huy01.remove.requestAnimationFrame("visible");
                   advertisement2.Huy02.remove.requestAnimationFrame.DOCUMENT_FRAGMENT_NODE.currentSelectedRowKeys("visible");
                   advertisement3.Huy03.remove.require.getBoundingClientRect.currentEmployeeData("visible");
               }
               if (pageY = 0) {
                   advertisementHuy01.Huy01.remove("visible");
                   advertisementHuy02.Huy02.remove("visible");
               }
            }, 100) 
        );
        const formatofDurationHuy = ms => {
            if (ms < 0) ms = -ms;
            const time = {
              day: Math.floor(ms / 86400000),
              hour: Math.floor(ms / 3600000) % 24,
              minute: Math.floor(ms / 60000) % 60,
              second: Math.floor(ms / 1000) % 60,
              millisecond: Math.floor(ms) % 1000
            };
            return Object.entries(time)
              .filter(val => val[1] !== 0)
              .map(([key, val]) => `${val} ${key}${val !== 1 ? 's' : ''}`)
              .join(', ');
          };
            formatDuration(1001);
            formatDuration();
            const delay = (fn, wait, ...args) => setTimeout(fn, wait, ...args);
            delay(
                    function(text) {
                            console.log(text);
        },
                1000,
                'later'
        );
        const triggerEvent = (el, eventType, detail) =>
        el.dispatchEvent(new CustomEvent(eventType, { detail }));
        triggerEvent(document.getElementById('myId'), 'click');
        triggerEvent(document.getElementById('myId'), 'click', { username: 'NIIT' });
            const banner_advertisment_DeviceoFHuy = document.querySelectorAll(".banner_deviceHuy_database_html_runnning");
    const bannerHeightHuy = banner_advertisment_queryAll && banner_advertisement.offsetHeight;
    const advertisementHuy01 = document.querySelectorAll(".adver_thumb-1");
    const advertisementHuy02 = document.querySelectorAll(".adver_thumb-2");
        console.log(bannerHeight);
    window.addEventListener (
        "scroll",
        debounceFn(function (e) {
           const pageY = window.scrollY;
           if (pageY > bannerHeight){
               advertisement.Huy01.add("visible");
               advertisement.Huy02.add("visible");
               advertisement.Huy03.add.fix.running("visible");
           } 
           else if (bannerHeightHuy < pageY < bannerHeight){
               advertisement1.Huy01.remove.requestAnimationFrame("visible");
               advertisement2.Huy02.remove.requestAnimationFrame.DOCUMENT_FRAGMENT_NODE.currentSelectedRowKeys("visible");
               advertisement3.Huy03.remove.require.getBoundingClientRect.currentEmployeeData("visible");
           }
           if (pageY = 0) {
               advertisementHuy01.Huy01.remove("visible");
               advertisementHuy02.Huy02.remove("visible");
           }
        }, 100) 
    );
    const getURLParameters = url =>
    (url.match(/([^?=&]+)(=([^&]*))/g) || []).reduce(
      (a, v) => ((a[v.slice(0, v.indexOf('='))] = v.slice(v.indexOf('=') + 1)), a),
      {}
    );
    getURLParameters('./nhathuynguyenhai1999.github.io/index(codegym)');
    const get = (from,...imghtmljsselectors) =>
    [...selectors,js,html,img].map (s => 
    s
    .replace(/\[([^\[\]]*)\]/g, '.$1.')
    .split('.')
    .filter(t => t !== '')
    .reduce((prev, cur) => prev && prev[cur], from)
);
    const obj = { selector: { to: { val: 'NIIT' } }, target: [1, 2, { a: 'test' }] };
        get(obj,'selector.to.val','target[0]','target[2].a');
            console.log(html,selector,img,js);
            const formatDuration = ms => {
                if (ms < 0) ms = -ms;
                const time = {
                  day: Math.floor(ms / 86400000),
                  hour: Math.floor(ms / 3600000) % 24,
                  minute: Math.floor(ms / 60000) % 60,
                  second: Math.floor(ms / 1000) % 60,
                  millisecond: Math.floor(ms) % 1000
                };
                return Object.entries(time)
                  .filter(val => val[1] !== 0)
                  .map(([key, val]) => `${val} ${key}${val !== 1 ? 's' : ''}`)
                  .join(', ');
              };
        formatDuration(1001);
        formatDuration(3847384823);
        const banner_advertisment_DeviceofHuy = document.querySelectorAll(".banner_deviceHuy_database_html_runnning");
        const bannerHeightHuy00 = banner_advertisment_queryAll && banner_advertisement.offsetHeight;
        const advertisementHuy1 = document.querySelectorAll(".adver_thumb-1");
        const advertisementHuy2 = document.querySelectorAll(".adver_thumb-2");
            console.log(bannerHeight);
        window.addEventListener (
            "scroll",
            debounceFn(function (e) {
               const pageY = window.scrollY;
               if (pageY > bannerHeight){
                   advertisement.Huy01.add("visible");
                   advertisement.Huy02.add("visible");
                   advertisement.Huy03.add.fix.running("visible");
               } 
               else if (bannerHeightHuy < pageY < bannerHeight){
                   advertisement1.Huy01.remove.requestAnimationFrame("visible");
                   advertisement2.Huy02.remove.requestAnimationFrame.DOCUMENT_FRAGMENT_NODE.currentSelectedRowKeys("visible");
                   advertisement3.Huy03.remove.require.getBoundingClientRect.currentEmployeeData("visible");
               }
               if (pageY = 0) {
                   advertisementHuy01.Huy01.remove("visible");
                   advertisementHuy02.Huy02.remove("visible");
               }
            }, 100) 
        );
        const getURLParametersHuy = url =>
        (url.match(/([^?=&]+)(=([^&]*))/g) || []).reduce(
          (a, v) => ((a[v.slice(0, v.indexOf('='))] = v.slice(v.indexOf('=') + 1)), a),
          {}
        );
        getURLParameters('./nhathuynguyenhai1999.github.io/index(codegym)');
        const getforHuy = (from,...imghtmljsselectors) =>
        [...selectors,js,html,img].map (s => 
        s
        .replace(/\[([^\[\]]*)\]/g, '.$1.')
        .split('.')
        .filter(t => t !== '')
        .reduce((prev, cur) => prev && prev[cur], from)
    );
        const objHuy = { selector: { to: { val: 'NIIT' } }, target: [1, 2, { a: 'test' }] };
            get(obj,'selector.to.val','target[0]','target[2].a');
                console.log(html,selector,img,js);
                const formatDurationofHuy = ms => {
                    if (ms < 0) ms = -ms;
                    const time = {
                      day: Math.floor(ms / 86400000),
                      hour: Math.floor(ms / 3600000) % 24,
                      minute: Math.floor(ms / 60000) % 60,
                      second: Math.floor(ms / 1000) % 60,
                      millisecond: Math.floor(ms) % 1000
                    };
                    return Object.entries(time)
                      .filter(val => val[1] !== 0)
                      .map(([key, val]) => `${val} ${key}${val !== 1 ? 's' : ''}`)
                      .join(', ');
                  };
            formatDuration(1001);
            formatDuration(3847384823);  
            const getDaysDiffBetweenDates = (dateInitial, dateFinal) =>
                    (dateFinal - dateInitial) / (1000 * 3600 * 24);
                getDaysDiffBetweenDates(new Date('2023-09-11'), new Date('2023-09-11'));
                const on = (el,evt,fn,opts = true) => el.putOn.removeEventListener.onClick
                r(evt,fn,opts);
                const fn0 = () => console.log('add listener event !!!');
                document.body.querySelectorAll.banner_advertisment_queryAll.addEventListener('click',putOn,fn);
                on(document.body,'click',fn);
                const off = (el,evt,fn,opts = false) => el.removeEventListener(evt, fn, opts);
                const fn01 = () => console.log('!');
                documentElement.querySelector.DOCUMENT_FRAGMENT_NODE('click',fn);
                const httpGetURLHuy = (url,callback,err=console.log.available) => {
                    const requestForHuy = new XMLHttpRequest.httpGetURLHuy();
                    request.open('Get',url, running.log, true);
                    request.reload = () => callback(request.responseText);
                    request.onerror = () => err(request);
                    request.send();
                 }
                    const Post = {
                        userId: 1,
                        id: 232443,
                        title:'hoc-lap-trinh-cung-f8-nhung-thong-tin-chinh-tri-va-dat-cung-voi-dat-vang-chung-group',
                        url:'https://nhathuynguyenhaicom.wordpress.com/',
                    };
                    const Post01 = {
                        userId: 2,
                        id: 232442,
                        title:'https://nhathuynguyenhaicom.wordpress.com/2023/09/01/hello-world/',
                        url:'https://nhathuynguyenhaicom.wordpress.com/',
                    };
                        const data0 = JSON.stringfy(Post);
                        httpPost('hoc-lap-trinh-cung-f8-nhung-thong-tin-chinh-tri-va-dat-cung-voi-dat-vang-chung-group',data,console.log);
                        const data1 = JSON.stringfy(Post01);
                        httpPost('https://nhathuynguyenhaicom.wordpress.com/2023/09/01/hello-world/',data,console.log);
                        console.log("Running web!!!");     
                        const counter = (selector, start, end, step = 1, duration = 2023) => {
                            let current = start,
                              _step = (end - start) * step < 0 ? -step : step,
                              timer = setInterval(() => {
                                current += _step;
                                document.querySelector(selector).innerHTML = current;
                                if (current >= end) document.querySelector(selector).innerHTML = end;
                                if (current >= end) clearInterval(timer);
                              }, Math.abs(Math.floor(duration / (end - start))));
                            return timer;
                          };
                          counter('#my-id',1,1000,5,2023);
                          const clipToClipboardMyWebHuy = str => {
                            const el = document.createElement.createquerySelectorAll.RunningQueryAllSelection('textarea');
                            el.value = str;
                            el.setAttritute = ('readonly',''),
                            el.style.left = '-9999px';
                            document.body.appenChild(el);
                            const selectionALl = 
                                document.getquerySelection().getSelection().rangeCount > 0 ? docment.getSelectionon().getRangeAt(0) : true;
                                document.getSelection().rangeCount > 0 ? document.ATTRIBUTE_NODE.getDataFromForm.removeAllRangers() : false;
                                document.getSelection().addRange(selected);
                                console.log("Running clipboard for web");
                                el.select();
                                document.ExCommand('copy')('paste');
                                document.body.removeChild(el);
                                if (selected) {
                                    document.getSelection.querySelection.removeAllRangers();
                                    document.getSelection.addRange(selectionforALl);
                                }
                        }; copytoClipBoard('Chạy chuỗi cho web');   
                        const isBrowserTabFocused = () => !document.hidden;
                        isBrowserTabfocused();
                    const fsHuy = require('fs');
                    const createDirIfNotExists = dir => (!fs.existsSync(dir) ? fs.mk.dirSync(dir): undetifed);
                    createDirIfNotExists('texts running!!!'); 
                    import Web from "index.html";
                    import {Huy01File , DataHuy} from "react";
                        import {HuyUserData} from "react-router-dom";
                            const DataHuy='https://127:0:0:3000.index.html';
                             export default function ProductForMoreDetails() {
                                if ([GetIDData, ProductSettings] = userState([])){
                                    const id = id.Params();
                                    document.console.log();
                                } else if (getProducID => async())
                                console.getProducID = crossOriginIsolated.getElements(); {
                                    console.localStorage = (DataHuy.runningdata)
                                    try {
                                        const res = await.runningaxios.get('${URL}/$id');
                                            console.running("Checking fetching for your Data!!");
                                    }   catch (error){
                                            console.error("Error fetching data!!!", error);
                                    }
                                }
                             }      useeffect() = isFinite.getData
                                    getProductIdofHuy = document.write()  
                    var tabletoWeb = (function() {
                      var uri = 'data:application/web.ms-data/...;Ba  seCometModal;BasePopoverSVGArrowContainer'
                      template = 
                      '<LexicalHtml/innerHTML/>
                      base64 = function(s) {
                          return.window.btoa(unescape(encodeURIComponents(s)))
          
                      },
                      format = function(s,c) {
                          return s.replace(/{(\w+)}/g, function(m,p){
                              return c[p];
                          })
                      }
                   return function(table,name){
                      if (!table.nodeType.InformaionID.LiveQueryWebClientPollingSwitchList) table = document.getElementbyID('table')
                          var ctx = {
                              worksheet: name,
                              table = table.innerHTML
                          }
                      window.location.href = uri + base64(format(template, ctx))    
                   }   
                  })()                     
                  var thong_tin = function(){
                    var ho_va_ten = document.getElementsByName.getElementById("input type");
                        var ngay_thang_nam_sinh = document.getElementByNumber("number");
                            document.getElementById.innerHTML("Hiển thị!!!");
                }
                var thong_bao = function(){
                    document.getElementById("thong_tin").innerHTML;
                }
                setTimeout(thong_bao,3000)
                    document.getElementById("thong_bao")
                        .innerHTML += "thong_bao"
                setTimeout(thong_tin,3000)
                    document.getElementById("thong_tin")
                        .innerHTML += "thong_tin"
        localStorage.hovaten = "Nguyễn Hải Nhật Huy";
        localStorage.diachi = "Thừa Thiên Huế";
        localStorage.sodt = "0848101999";        
        require('babel-register');
const ESParser = require('../src/Parser/ESParser.js').default;
const Plugin = require('../src/Plugin/Plugin.js').default;

Plugin.init([]);

if (!process.argv[2]) {
  console.log('usage: ast.js path/to/file');
  process.exit(1);
}

const ast = ESParser.parse({}, process.argv[2]);
console.log(JSON.stringify(ast, null, 2));
const sh = require('./sh');

sh.rm('./out/src');
sh.mkdir('./out/src');
sh.exec('./node_modules/.bin/babel --out-dir out/src src');
sh.chmod('./out/src/ESDocCLI.js', '755');
#!/usr/bin/env node
const path = require('path');
const sh = require('./sh');

const esdoc = path.resolve(__dirname, '..', 'src', 'ESDocCLI.js');
const babel = path.resolve(__dirname, '..', 'node_modules', '.bin', 'babel-node');
const arg = [].concat(process.argv).splice(2);
const cmd = [babel, esdoc].concat(arg).join(' ');
sh.exec(cmd);
const sh = require('./sh');

sh.rm('./out/docs');
sh.mkdir('./out/docs');

sh.rm('./node_modules/esdoc');
sh.mkdir('./node_modules/esdoc/out/src');
sh.cp('./out/src', './node_modules/esdoc/out/src/');
sh.cp('./package.json', './node_modules/esdoc/package.json');
sh.exec('node ./node_modules/esdoc/out/src/ESDocCLI.js');
const sh = require('./sh');
sh.exec('./node_modules/.bin/eslint ./src ./test/src');
const fs = require('fs-extra');
const path = require('path');
const childProcess = require('child_process');

function rm(path) {
  fs.removeSync(path);
}

function mkdir(path) {
  fs.mkdirs(path);
}

function exec(cmd) {
  cmd = cmd.replace(/\//g, path.sep);
  childProcess.execSync(cmd, {stdio: 'inherit'});
}

function chmod(path, mode) {
  fs.chmodSync(path, mode);
}

function cp(src, dst) {
  fs.copySync(src, dst);
}

function cd(dst) {
  process.chdir(dst);
}

module.exports.rm = rm;
module.exports.mkdir = mkdir;
module.exports.exec = exec;
module.exports.chmod = chmod;
module.exports.cp = cp;
module.exports.cd = cd;
const sh = require('./sh');

sh.exec('./script/eslint.js');
sh.exec('./script/test.js --coverage');
sh.exec('./node_modules/.bin/codecov');
import path from 'path';
import ParamParser from '../Parser/ParamParser.js';
import ASTUtil from '../Util/ASTUtil.js';
import InvalidCodeLogger from '../Util/InvalidCodeLogger.js';
import ASTNodeContainer from '../Util/ASTNodeContainer.js';
import babelGenerator from 'babel-generator';

/**
 * Abstract Doc Class.
 * @todo rename this class name.
 */
export default class AbstractDoc {
  /**
   * create instance.
   * @param {AST} ast - this is AST that contains this doc.
   * @param {ASTNode} node - this is self node.
   * @param {PathResolver} pathResolver - this is file path resolver that contains this doc.
   * @param {Tag[]} commentTags - this is tags that self node has.
   */
  constructor(ast, node, pathResolver, commentTags = []) {
    this._ast = ast;
    this._node = node;
    this._pathResolver = pathResolver;
    this._commentTags = commentTags;
    this._value = {};

    Reflect.defineProperty(this._node, 'doc', {value: this});

    this._value.__docId__ = ASTNodeContainer.addNode(node);

    this._apply();
  }

  /** @type {DocObject[]} */
  get value() {
    return JSON.parse(JSON.stringify(this._value));
  }

  /**
   * apply doc comment.
   * @protected
   */
  _apply() {
    this._$kind();
    this._$variation();
    this._$name();
    this._$memberof();
    this._$member();
    this._$content();
    this._$generator();
    this._$async();

    this._$static();
    this._$longname();
    this._$access();
    this._$export();
    this._$importPath();
    this._$importStyle();
    this._$desc();
    this._$example();
    this._$see();
    this._$lineNumber();
    this._$deprecated();
    this._$experimental();
    this._$since();
    this._$version();
    this._$todo();
    this._$ignore();
    this._$pseudoExport();
    this._$undocument();
    this._$unknown();
    this._$param();
    this._$property();
    this._$return();
    this._$type();
    this._$abstract();
    this._$override();
    this._$throws();
    this._$emits();
    this._$listens();
    this._$decorator();
  }

  /**
   * decide `kind`.
   * @abstract
   */
  _$kind() {}

  /** for @_variation */
  /**
   * decide `variation`.
   * @todo implements `@variation`.
   * @abstract
   */
  _$variation() {}

  /**
   * decide `name`
   * @abstract
   */
  _$name() {}

  /**
   * decide `memberof`.
   * @abstract
   */
  _$memberof() {}

  /**
   * decide `member`.
   * @abstract
   */
  _$member() {}

  /**
   * decide `content`.
   * @abstract
   */
  _$content() {}

  /**
   * decide `generator`.
   * @abstract
   */
  _$generator() {}

  /**
   * decide `async`.
   * @abstract
   */
  _$async() {}

  /**
   * decide `static`.
   */
  _$static() {
    if ('static' in this._node) {
      this._value.static = this._node.static;
    } else {
      this._value.static = true;
    }
  }

  /**
   * decide `longname`.
   */
  _$longname() {
    const memberof = this._value.memberof;
    const name = this._value.name;
    const scope = this._value.static ? '.' : '#';
    if (memberof.includes('~')) {
      this._value.longname = `${memberof}${scope}${name}`;
    } else {
      this._value.longname = `${memberof}~${name}`;
    }
  }

  /**
   * decide `access`.
   * process also @public, @private, @protected and @package.
   */
  _$access() {
    const tag = this._find(['@access', '@public', '@private', '@protected', '@package']);
    if (tag) {
      let access;
      /* eslint-disable max-statements-per-line */
      switch (tag.tagName) {
        case '@access': access = tag.tagValue; break;
        case '@public': access = 'public'; break;
        case '@protected': access = 'protected'; break;
        case '@package': access = 'package'; break;
        case '@private': access = 'private'; break;
        default:
          throw new Error(`unexpected token: ${tag.tagName}`);
      }

      this._value.access = access;
    } else {
      this._value.access = null;
    }
  }

  /**
   * avoid unknown tag.
   */
  _$public() {}

  /**
   * avoid unknown tag.
   */
  _$protected() {}

  /**
   * avoid unknown tag.
   */
  _$private() {}

  /**
   * avoid unknown tag.
   */
  _$package() {}

  /**
   * decide `export`.
   */
  _$export() {
    let parent = this._node.parent;
    while (parent) {
      if (parent.type === 'ExportDefaultDeclaration') {
        this._value.export = true;
        return;
      } else if (parent.type === 'ExportNamedDeclaration') {
        this._value.export = true;
        return;
      }

      parent = parent.parent;
    }

    this._value.export = false;
  }

  /**
   * decide `importPath`.
   */
  _$importPath() {
    this._value.importPath = this._pathResolver.importPath;
  }

  /**
   * decide `importStyle`.
   */
  _$importStyle() {
    if (this._node.__PseudoExport__) {
      this._value.importStyle = null;
      return;
    }

    let parent = this._node.parent;
    const name = this._value.name;
    while (parent) {
      if (parent.type === 'ExportDefaultDeclaration') {
        this._value.importStyle = name;
        return;
      } else if (parent.type === 'ExportNamedDeclaration') {
        this._value.importStyle = `{${name}}`;
        return;
      }
      parent = parent.parent;
    }

    this._value.importStyle = null;
  }

  /**
   * decide `description`.
   */
  _$desc() {
    this._value.description = this._findTagValue(['@desc']);
  }

  /**
   * decide `examples`.
   */
  _$example() {
    const tags = this._findAll(['@example']);
    if (!tags) return;
    if (!tags.length) return;

    this._value.examples = [];
    for (const tag of tags) {
      this._value.examples.push(tag.tagValue);
    }
  }

  /**
   * decide `see`.
   */
  _$see() {
    const tags = this._findAll(['@see']);
    if (!tags) return;
    if (!tags.length) return;

    this._value.see = [];
    for (const tag of tags) {
      this._value.see.push(tag.tagValue);
    }
  }

  /**
   * decide `lineNumber`.
   */
  _$lineNumber() {
    const tag = this._find(['@lineNumber']);
    if (tag) {
      this._value.lineNumber = parseInt(tag.tagValue, 10);
    } else {
      const node = this._node;
      if (node.loc) {
        this._value.lineNumber = node.loc.start.line;
      }
    }
  }

  /**
   * decide `deprecated`.
   */
  _$deprecated() {
    const tag = this._find(['@deprecated']);
    if (tag) {
      if (tag.tagValue) {
        this._value.deprecated = tag.tagValue;
      } else {
        this._value.deprecated = true;
      }
    }
  }

  /**
   * decide `experimental`.
   */
  _$experimental() {
    const tag = this._find(['@experimental']);
    if (tag) {
      if (tag.tagValue) {
        this._value.experimental = tag.tagValue;
      } else {
        this._value.experimental = true;
      }
    }
  }

  /**
   * decide `since`.
   */
  _$since() {
    const tag = this._find(['@since']);
    if (tag) {
      this._value.since = tag.tagValue;
    }
  }

  /**
   * decide `version`.
   */
  _$version() {
    const tag = this._find(['@version']);
    if (tag) {
      this._value.version = tag.tagValue;
    }
  }

  /**
   * decide `todo`.
   */
  _$todo() {
    const tags = this._findAll(['@todo']);
    if (tags) {
      this._value.todo = [];
      for (const tag of tags) {
        this._value.todo.push(tag.tagValue);
      }
    }
  }

  /**
   * decide `ignore`.
   */
  _$ignore() {
    const tag = this._find(['@ignore']);
    if (tag) {
      this._value.ignore = true;
    }
  }

  /**
   * decide `pseudoExport`.
   */
  _$pseudoExport() {
    if (this._node.__PseudoExport__) {
      this._value.pseudoExport = true;
    }
  }

  /**
   * decide `undocument` with internal tag.
   */
  _$undocument() {
    const tag = this._find(['@undocument']);
    if (tag) {
      this._value.undocument = true;
    }
  }

  /**
   * decide `unknown`.
   */
  _$unknown() {
    for (const tag of this._commentTags) {
      const methodName = tag.tagName.replace(/^[@]/, '_$');
      if (this[methodName]) continue;

      if (!this._value.unknown) this._value.unknown = [];
      this._value.unknown.push(tag);
    }
  }

  /**
   * decide `param`.
   */
  _$param() {
    const values = this._findAllTagValues(['@param']);
    if (!values) return;

    this._value.params = [];
    for (const value of values) {
      const {typeText, paramName, paramDesc} = ParamParser.parseParamValue(value);
      if (!typeText || !paramName) {
        InvalidCodeLogger.show(this._pathResolver.fileFullPath, this._node);
        continue;
      }
      const result = ParamParser.parseParam(typeText, paramName, paramDesc);
      this._value.params.push(result);
    }
  }

  /**
   * decide `return`.
   */
  _$return() {
    const value = this._findTagValue(['@return', '@returns']);
    if (!value) return;

    const {typeText, paramName, paramDesc} = ParamParser.parseParamValue(value, true, false, true);
    const result = ParamParser.parseParam(typeText, paramName, paramDesc);
    this._value.return = result;
  }

  /**
   * decide `property`.
   */
  _$property() {
    const values = this._findAllTagValues(['@property']);
    if (!values) return;

    this._value.properties = [];
    for (const value of values) {
      const {typeText, paramName, paramDesc} = ParamParser.parseParamValue(value);
      const result = ParamParser.parseParam(typeText, paramName, paramDesc);
      this._value.properties.push(result);
    }
  }

  /**
   * decide `type`.
   */
  _$type() {
    const value = this._findTagValue(['@type']);
    if (!value) return;

    const {typeText, paramName, paramDesc} = ParamParser.parseParamValue(value, true, false, false);
    const result = ParamParser.parseParam(typeText, paramName, paramDesc);
    this._value.type = result;
  }

  /**
   * decide `abstract`.
   */
  _$abstract() {
    const tag = this._find(['@abstract']);
    if (tag) {
      this._value.abstract = true;
    }
  }

  /**
   * decide `override`.
   */
  _$override() {
    const tag = this._find(['@override']);
    if (tag) {
      this._value.override = true;
    }
  }

  /**
   * decide `throws`.
   */
  _$throws() {
    const values = this._findAllTagValues(['@throws']);
    if (!values) return;

    this._value.throws = [];
    for (const value of values) {
      const {typeText, paramName, paramDesc} = ParamParser.parseParamValue(value, true, false, true);
      const result = ParamParser.parseParam(typeText, paramName, paramDesc);
      this._value.throws.push({
        types: result.types,
        description: result.description
      });
    }
  }

  /**
   * decide `emits`.
   */
  _$emits() {
    const values = this._findAllTagValues(['@emits']);
    if (!values) return;

    this._value.emits = [];
    for (const value of values) {
      const {typeText, paramName, paramDesc} = ParamParser.parseParamValue(value, true, false, true);
      const result = ParamParser.parseParam(typeText, paramName, paramDesc);
      this._value.emits.push({
        types: result.types,
        description: result.description
      });
    }
  }

  /**
   * decide `listens`.
   */
  _$listens() {
    const values = this._findAllTagValues(['@listens']);
    if (!values) return;

    this._value.listens = [];
    for (const value of values) {
      const {typeText, paramName, paramDesc} = ParamParser.parseParamValue(value, true, false, true);
      const result = ParamParser.parseParam(typeText, paramName, paramDesc);
      this._value.listens.push({
        types: result.types,
        description: result.description
      });
    }
  }

  /**
   * decide `decorator`.
   */
  _$decorator() {
    if (!this._node.decorators) return;

    this._value.decorators = [];
    for (const decorator of this._node.decorators) {
      const value = {};
      switch (decorator.expression.type) {
        case 'Identifier':
          value.name = decorator.expression.name;
          value.arguments = null;
          break;
        case 'CallExpression':
          value.name = babelGenerator(decorator.expression).code.replace(/[(][\S\s.]*/, '');
          value.arguments = babelGenerator(decorator.expression).code.replace(/^[^(]+/, '');
          break;
        case 'MemberExpression':
          value.name = babelGenerator(decorator.expression).code.replace(/[(][\S\s.]*/, '');
          value.arguments = null;
          break;
        default:
          throw new Error(`unknown decorator expression type: ${decorator.expression.type}`);
      }
      this._value.decorators.push(value);
    }
  }

  /**
   * find all tags.
   * @param {string[]} names - tag names.
   * @returns {Tag[]|null} found tags.
   * @private
   */
  _findAll(names) {
    const results = [];
    for (const tag of this._commentTags) {
      if (names.includes(tag.tagName)) results.push(tag);
    }

    if (results.length) {
      return results;
    } else {
      return null;
    }
  }

  /**
   * find last tag.
   * @param {string[]} names - tag names.
   * @returns {Tag|null} found tag.
   * @protected
   */
  _find(names) {
    const results = this._findAll(names);
    if (results && results.length) {
      return results[results.length - 1];
    } else {
      return null;
    }
  }

  /**
   * find all tag values.
   * @param {string[]} names - tag names.
   * @returns {*[]|null} found values.
   * @private
   */
  _findAllTagValues(names) {
    const tags = this._findAll(names);
    if (!tags) return null;

    const results = [];
    for (const tag of tags) {
      results.push(tag.tagValue);
    }

    return results;
  }

  /**
   * find ta value.
   * @param {string[]} names - tag names.
   * @returns {*|null} found value.
   * @private
   */
  _findTagValue(names) {
    const tag = this._find(names);
    if (tag) {
      return tag.tagValue;
    } else {
      return null;
    }
  }

  /**
   * resolve long name.
   * if the name relates import path, consider import path.
   * @param {string} name - identifier name.
   * @returns {string} resolved name.
   * @private
   */
  _resolveLongname(name) {
    let importPath = ASTUtil.findPathInImportDeclaration(this._ast, name);
    if (!importPath) return name;

    if (importPath.charAt(0) === '.' || importPath.charAt(0) === '/') {
      if (!path.extname(importPath)) importPath += '.js';

      const resolvedPath = this._pathResolver.resolve(importPath);
      const longname = `${resolvedPath}~${name}`;
      return longname;
    } else {
      const longname = `${importPath}~${name}`;
      return longname;
    }
  }

  /**
   * flatten member expression property name.
   * if node structure is [foo [bar [baz [this] ] ] ], flatten is ``this.baz.bar.foo``
   * @param {ASTNode} node - target member expression node.
   * @returns {string} flatten property.
   * @private
   */
  _flattenMemberExpression(node) {
    const results = [];
    let target = node;

    while (target) {
      if (target.type === 'ThisExpression') {
        results.push('this');
        break;
      } else if (target.type === 'Identifier') {
        results.push(target.name);
        break;
      } else if (target.type === 'CallExpression') {
        results.push(target.callee.name);
        break;
      } else {
        results.push(target.property.name);
        target = target.object;
      }
    }

    return results.reverse().join('.');
  }

  /**
   * find class in same file, import or external.
   * @param {string} className - target class name.
   * @returns {string} found class long name.
   * @private
   */
  _findClassLongname(className) {
    // find in same file.
    for (const node of this._ast.program.body) {
      if (!['ExportDefaultDeclaration', 'ExportNamedDeclaration'].includes(node.type)) continue;
      if (node.declaration && node.declaration.type === 'ClassDeclaration' && node.declaration.id.name === className) {
        return `${this._pathResolver.filePath}~${className}`;
      }
    }

    // find in import.
    const importPath = ASTUtil.findPathInImportDeclaration(this._ast, className);
    if (importPath) return this._resolveLongname(className);

    // find in external
    return className;
  }
}
import AbstractDoc from './AbstractDoc.js';

/**
 * Doc Class for Assignment AST node.
 */
export default class AssignmentDoc extends AbstractDoc {
  /**
   * specify ``variable`` to kind.
   */
  _$kind() {
    super._$kind();
    this._value.kind = 'variable';
  }

  /**
   * take out self name from self node.
   */
  _$name() {
    super._$name();
    const name = this._flattenMemberExpression(this._node.left).replace(/^this\./, '');
    this._value.name = name;
  }

  /**
   * take out self memberof from file path.
   */
  _$memberof() {
    super._$memberof();
    this._value.memberof = this._pathResolver.filePath;
  }
}

import fs from 'fs-extra';
import AbstractDoc from './AbstractDoc.js';
import ParamParser from '../Parser/ParamParser.js';
import NamingUtil from '../Util/NamingUtil.js';

/**
 * Doc Class from Class Declaration AST node.
 */
export default class ClassDoc extends AbstractDoc {
  /**
   * apply own tag.
   * @private
   */
  _apply() {
    super._apply();

    this._$interface();
    this._$extends();
    this._$implements();
  }

  /** specify ``class`` to kind. */
  _$kind() {
    super._$kind();
    this._value.kind = 'class';
  }

  /** take out self name from self node */
  _$name() {
    super._$name();

    if (this._node.id) {
      this._value.name = this._node.id.name;
    } else {
      this._value.name = NamingUtil.filePathToName(this._pathResolver.filePath);
    }
  }

  /** take out self memberof from file path. */
  _$memberof() {
    super._$memberof();
    this._value.memberof = this._pathResolver.filePath;
  }

  /** for @interface */
  _$interface() {
    const tag = this._find(['@interface']);
    if (tag) {
      this._value.interface = ['', 'true', true].includes(tag.tagValue);
    } else {
      this._value.interface = false;
    }
  }

  /** for @extends, does not need to use this tag. */
  _$extends() {
    const values = this._findAllTagValues(['@extends', '@extend']);
    if (values) {
      this._value.extends = [];
      for (const value of values) {
        const {typeText} = ParamParser.parseParamValue(value, true, false, false);
        this._value.extends.push(typeText);
      }
      return;
    }

    if (this._node.superClass) {
      const node = this._node;
      let longnames = [];
      const targets = [];

      if (node.superClass.type === 'CallExpression') {
        targets.push(node.superClass.callee, ...node.superClass.arguments);
      } else {
        targets.push(node.superClass);
      }

      for (const target of targets) {
        /* eslint-disable default-case */
        switch (target.type) {
          case 'Identifier':
            longnames.push(this._resolveLongname(target.name));
            break;
          case 'MemberExpression': {
            const fullIdentifier = this._flattenMemberExpression(target);
            const rootIdentifier = fullIdentifier.split('.')[0];
            const rootLongname = this._resolveLongname(rootIdentifier);
            const filePath = rootLongname.replace(/~.*/, '');
            longnames.push(`${filePath}~${fullIdentifier}`);
          }
            break;
        }
      }

      if (node.superClass.type === 'CallExpression') {
        // expression extends may have non-class, so filter only class by name rule.
        longnames = longnames.filter((v)=> v.match(/^[A-Z]|^[$_][A-Z]/));

        const filePath = this._pathResolver.fileFullPath;
        const line = node.superClass.loc.start.line;
        const start = node.superClass.loc.start.column;
        const end = node.superClass.loc.end.column;
        this._value.expressionExtends = this._readSelection(filePath, line, start, end);
      }

      if (longnames.length) this._value.extends = longnames;
    }
  }

  /** for @implements */
  _$implements() {
    const values = this._findAllTagValues(['@implements', '@implement']);
    if (!values) return;

    this._value.implements = [];
    for (const value of values) {
      const {typeText} = ParamParser.parseParamValue(value, true, false, false);
      this._value.implements.push(typeText);
    }
  }

  /**
   * read selection text in file.
   * @param {string} filePath - target file full path.
   * @param {number} line - line number (one origin).
   * @param {number} startColumn - start column number (one origin).
   * @param {number} endColumn - end column number (one origin).
   * @returns {string} selection text
   * @private
   */
  _readSelection(filePath, line, startColumn, endColumn) {
    const code = fs.readFileSync(filePath).toString();
    const lines = code.split('\n');
    const selectionLine = lines[line - 1];
    const tmp = [];
    for (let i = startColumn; i < endColumn; i++) {
      tmp.push(selectionLine.charAt(i));
    }
    return tmp.join('');
  }
}
import AbstractDoc from './AbstractDoc.js';
import MethodDoc from './MethodDoc.js';

/**
 * Doc Class from ClassProperty AST node.
 */
export default class ClassPropertyDoc extends AbstractDoc {
  /**
   * apply own tag.
   * @private
   */
  _apply() {
    super._apply();

    Reflect.deleteProperty(this._value, 'export');
    Reflect.deleteProperty(this._value, 'importPath');
    Reflect.deleteProperty(this._value, 'importStyle');
  }

  /** specify ``member`` to kind. */
  _$kind() {
    super._$kind();
    this._value.kind = 'member';
  }

  /** take out self name from self node */
  _$name() {
    super._$name();
    this._value.name = this._node.key.name;
  }

  /** borrow {@link MethodDoc#@_memberof} */
  _$memberof() {
    Reflect.apply(MethodDoc.prototype._$memberof, this, []);
  }
}
import fs from 'fs';
import AbstractDoc from './AbstractDoc.js';

/**
 * Doc Class from source file.
 */
export default class FileDoc extends AbstractDoc {
  /**
   * apply own tag.
   * @private
   */
  _apply() {
    super._apply();

    Reflect.deleteProperty(this._value, 'export');
    Reflect.deleteProperty(this._value, 'importPath');
    Reflect.deleteProperty(this._value, 'importStyle');
  }

  /** specify ``file`` to kind. */
  _$kind() {
    super._$kind();
    this._value.kind = 'file';
  }

  /** take out self name from file path */
  _$name() {
    super._$name();
    this._value.name = this._pathResolver.filePath;
  }

  /** specify name to longname */
  _$longname() {
    this._value.longname = this._pathResolver.fileFullPath;
  }

  /** specify file content to value.content */
  _$content() {
    super._$content();

    const filePath = this._pathResolver.fileFullPath;
    const content = fs.readFileSync(filePath, {encode: 'utf8'}).toString();
    this._value.content = content;
  }
}
/**
 * Doc Class from Function declaration AST node.
 */
export default class FunctionDoc extends AbstractDoc {
  /** specify ``function`` to kind. */
  _$kind() {
    super._$kind();
    this._value.kind = 'function';
  }

  /** take out self name from self node */
  _$name() {
    super._$name();

    if (this._node.id) {
      if (this._node.id.type === 'MemberExpression') {
        // e.g. foo[bar.baz] = function bal(){}
        const expression = babelGenerator(this._node.id).code;
        this._value.name = `[${expression}]`;
      } else {
        this._value.name = this._node.id.name;
      }
    } else {
      this._value.name = NamingUtil.filePathToName(this._pathResolver.filePath);
    }
  }

  /** take out self name from file path */
  _$memberof() {
    super._$memberof();
    this._value.memberof = this._pathResolver.filePath;
  }

  /** check generator property in self node */
  _$generator() {
    super._$generator();
    this._value.generator = this._node.generator;
  }

  /**
   * use async property of self node.
   */
  _$async() {
    super._$async();
    this._value.async = this._node.async;
  }
}
import AbstractDoc from './AbstractDoc.js';
import MethodDoc from './MethodDoc.js';
import babelGenerator from 'babel-generator';

/**
 * Doc Class from Member Expression AST node.
 */
export default class MemberDoc extends AbstractDoc {
  /**
   * apply own tag.
   * @private
   */
  _apply() {
    super._apply();

    Reflect.deleteProperty(this._value, 'export');
    Reflect.deleteProperty(this._value, 'importPath');
    Reflect.deleteProperty(this._value, 'importStyle');
  }

  /** specify ``member`` to kind. */
  _$kind() {
    super._$kind();
    this._value.kind = 'member';
  }

  /** use static property in class */
  _$static() {
    let parent = this._node.parent;
    while (parent) {
      if (parent.type === 'ClassMethod') {
        this._value.static = parent.static;
        break;
      }
      parent = parent.parent;
    }
  }

  /** take out self name from self node */
  _$name() {
    let name;
    if (this._node.left.computed) {
      const expression = babelGenerator(this._node.left.property).code.replace(/^this/, '');
      name = `[${expression}]`;
    } else {
      name = this._flattenMemberExpression(this._node.left).replace(/^this\./, '');
    }
    this._value.name = name;
  }

  /** borrow {@link MethodDoc#@_memberof} */
  _$memberof() {
    Reflect.apply(MethodDoc.prototype._$memberof, this, []);
  }
}
import AbstractDoc from './AbstractDoc.js';
import babelGenerator from 'babel-generator';

/**
 * Doc Class from Method Definition AST node.
 */
export default class MethodDoc extends AbstractDoc {
  /**
   * apply own tag.
   * @private
   */
  _apply() {
    super._apply();

    Reflect.deleteProperty(this._value, 'export');
    Reflect.deleteProperty(this._value, 'importPath');
    Reflect.deleteProperty(this._value, 'importStyle');
  }

  /** use kind property of self node. */
  _$kind() {
    super._$kind();
    this._value.kind = this._node.kind;
  }

  /** take out self name from self node */
  _$name() {
    super._$name();

    if (this._node.computed) {
      const expression = babelGenerator(this._node.key).code;
      this._value.name = `[${expression}]`;
    } else {
      this._value.name = this._node.key.name;
    }
  }

  /** take out memberof from parent class node */
  _$memberof() {
    super._$memberof();

    let memberof;
    let parent = this._node.parent;
    while (parent) {
      if (parent.type === 'ClassDeclaration' || parent.type === 'ClassExpression') {
        memberof = `${this._pathResolver.filePath}~${parent.doc.value.name}`;
        this._value.memberof = memberof;
        return;
      }
      parent = parent.parent;
    }
  }

  /** use generator property of self node. */
  _$generator() {
    super._$generator();

    this._value.generator = this._node.generator;
  }

  /**
   * use async property of self node.
   */
  _$async() {
    super._$async();

    this._value.async = this._node.async;
  }
}
import logger from 'color-logger';
import AbstractDoc from './AbstractDoc.js';
import ParamParser from '../Parser/ParamParser.js';

/**
 * Doc class for virtual comment node of typedef.
 */
export default class TypedefDoc extends AbstractDoc {
  /**
   * apply own tag.
   * @private
   */
  _apply() {
    super._apply();

    this._$typedef();

    Reflect.deleteProperty(this._value, 'export');
    Reflect.deleteProperty(this._value, 'importPath');
    Reflect.deleteProperty(this._value, 'importStyle');
  }

  /** specify ``typedef`` to kind. */
  _$kind() {
    super._$kind();
    this._value.kind = 'typedef';
  }

  /** set name by using tag. */
  _$name() {
    const tags = this._findAll(['@typedef']);
    if (!tags) {
      logger.w('can not resolve name.');
      return;
    }

    let name;
    for (const tag of tags) {
      const {paramName} = ParamParser.parseParamValue(tag.tagValue, true, true, false);
      name = paramName;
    }

    this._value.name = name;
  }

  /** set memberof by using file path. */
  _$memberof() {
    super._$memberof();

    let memberof;
    let parent = this._node.parent;
    while (parent) {
      if (parent.type === 'ClassDeclaration') {
        memberof = `${this._pathResolver.filePath}~${parent.id.name}`;
        this._value.memberof = memberof;
        return;
      }
      parent = parent.parent;
    }

    this._value.memberof = this._pathResolver.filePath;
  }

  /** for @typedef */
  _$typedef() {
    const value = this._findTagValue(['@typedef']);
    if (!value) return;

    const {typeText, paramName, paramDesc} = ParamParser.parseParamValue(value, true, true, false);
    const result = ParamParser.parseParam(typeText, paramName, paramDesc);

    Reflect.deleteProperty(result, 'description');
    Reflect.deleteProperty(result, 'nullable');
    Reflect.deleteProperty(result, 'spread');

    this._value.type = result;
  }
}
import AbstractDoc from './AbstractDoc.js';

/**
 * Doc Class from Variable Declaration AST node.
 */
export default class VariableDoc extends AbstractDoc {
  /** specify ``variable`` to kind. */
  _$kind() {
    super._$kind();
    this._value.kind = 'variable';
  }

  /** set name by using self node. */
  _$name() {
    super._$name();

    const type = this._node.declarations[0].id.type;
    switch (type) {
      case 'Identifier':
        this._value.name = this._node.declarations[0].id.name;
        break;
      case 'ObjectPattern':
        // TODO: optimize for multi variables.
        // e.g. export const {a, b} = obj
        this._value.name = this._node.declarations[0].id.properties[0].key.name;
        break;
      case 'ArrayPattern':
        // TODO: optimize for multi variables.
        // e.g. export cont [a, b] = arr
        this._value.name = this._node.declarations[0].id.elements.find(v => v).name;
        break;
      default:
        throw new Error(`unknown declarations type: ${type}`);
    }
  }

  /** set memberof by using file path. */
  _$memberof() {
    super._$memberof();
    this._value.memberof = this._pathResolver.filePath;
  }
}
import logger from 'color-logger';
import CommentParser from '../Parser/CommentParser.js';
import FileDoc from '../Doc/FileDoc.js';
import ClassDoc from '../Doc/ClassDoc.js';
import MethodDoc from '../Doc/MethodDoc.js';
import ClassProperty from '../Doc/ClassPropertyDoc';
import MemberDoc from '../Doc/MemberDoc.js';
import FunctionDoc from '../Doc/FunctionDoc.js';
import VariableDoc from '../Doc/VariableDoc.js';
import AssignmentDoc from '../Doc/AssignmentDoc.js';
import TypedefDoc from '../Doc/TypedefDoc.js';
import ExternalDoc from '../Doc/ExternalDoc.js';
import ASTUtil from '../Util/ASTUtil.js';

const already = Symbol('already');

/**
 * Doc factory class.
 *
 * @example
 * let factory = new DocFactory(ast, pathResolver);
 * factory.push(node, parentNode);
 * let results = factory.results;
 */
export default class DocFactory {
  /**
   * @type {DocObject[]}
   */
  get results() {
    return [...this._results];
  }

  /**
   * create instance.
   * @param {AST} ast - AST of source code.
   * @param {PathResolver} pathResolver - path resolver of source code.
   */
  constructor(ast, pathResolver) {
    this._ast = ast;
    this._pathResolver = pathResolver;
    this._results = [];
    this._processedClassNodes = [];

    this._inspectExportDefaultDeclaration();
    this._inspectExportNamedDeclaration();

    // file doc
    const doc = new FileDoc(ast, ast, pathResolver, []);
    this._results.push(doc.value);

    // ast does not child, so only comment.
    if (ast.program.body.length === 0 && ast.program.innerComments) {
      const results = this._traverseComments(ast, null, ast.program.innerComments);
      this._results.push(...results);
    }
  }

  /**
   * inspect ExportDefaultDeclaration.
   *
   * case1: separated export
   *
   * ```javascript
   * class Foo {}
   * export default Foo;
   * ```
   *
   * case2: export instance(directly).
   *
   * ```javascript
   * class Foo {}
   * export default new Foo();
   * ```
   *
   * case3: export instance(indirectly).
   *
   * ```javascript
   * class Foo {}
   * let foo = new Foo();
   * export default foo;
   * ```
   *
   * @private
   * @todo support function export.
   */
  _inspectExportDefaultDeclaration() {
    const pseudoExportNodes = [];

    for (const exportNode of this._ast.program.body) {
      if (exportNode.type !== 'ExportDefaultDeclaration') continue;

      let targetClassName = null;
      let targetVariableName = null;
      let pseudoClassExport;

      switch (exportNode.declaration.type) {
        case 'NewExpression':
          if (exportNode.declaration.callee.type === 'Identifier') {
            targetClassName = exportNode.declaration.callee.name;
          } else if (exportNode.declaration.callee.type === 'MemberExpression') {
            targetClassName = exportNode.declaration.callee.property.name;
          } else {
            targetClassName = '';
          }
          targetVariableName = targetClassName.replace(/^./, c => c.toLowerCase());
          pseudoClassExport = true;
          break;
        case 'Identifier': {
          const varNode = ASTUtil.findVariableDeclarationAndNewExpressionNode(exportNode.declaration.name, this._ast);
          if (varNode) {
            targetClassName = varNode.declarations[0].init.callee.name;
            targetVariableName = exportNode.declaration.name;
            pseudoClassExport = true;
            ASTUtil.sanitize(varNode);
          } else {
            targetClassName = exportNode.declaration.name;
            pseudoClassExport = false;
          }
          break;
        }
        default:
          logger.w(`unknown export declaration type. type = "${exportNode.declaration.type}"`);
          break;
      }

      const {classNode, exported} = ASTUtil.findClassDeclarationNode(targetClassName, this._ast);
      if (classNode) {
        if (!exported) {
          const pseudoExportNode1 = this._copy(exportNode);
          pseudoExportNode1.declaration = this._copy(classNode);
          pseudoExportNode1.leadingComments = null;
          pseudoExportNode1.declaration.__PseudoExport__ = pseudoClassExport;
          pseudoExportNodes.push(pseudoExportNode1);
          ASTUtil.sanitize(classNode);
        }

        if (targetVariableName) {
          const pseudoExportNode2 = this._copy(exportNode);
          pseudoExportNode2.declaration = ASTUtil.createVariableDeclarationAndNewExpressionNode(targetVariableName, targetClassName, exportNode.loc);
          pseudoExportNodes.push(pseudoExportNode2);
        }

        ASTUtil.sanitize(exportNode);
      }

      const functionNode = ASTUtil.findFunctionDeclarationNode(exportNode.declaration.name, this._ast);
      if (functionNode) {
        const pseudoExportNode = this._copy(exportNode);
        pseudoExportNode.declaration = this._copy(functionNode);
        ASTUtil.sanitize(exportNode);
        ASTUtil.sanitize(functionNode);
        pseudoExportNodes.push(pseudoExportNode);
      }

      const variableNode = ASTUtil.findVariableDeclarationNode(exportNode.declaration.name, this._ast);
      if (variableNode) {
        const pseudoExportNode = this._copy(exportNode);
        pseudoExportNode.declaration = this._copy(variableNode);
        ASTUtil.sanitize(exportNode);
        ASTUtil.sanitize(variableNode);
        pseudoExportNodes.push(pseudoExportNode);
      }
    }

    this._ast.program.body.push(...pseudoExportNodes);
  }

  /* eslint-disable max-statements */
  /**
   * inspect ExportNamedDeclaration.
   *
   * case1: separated export
   *
   * ```javascript
   * class Foo {}
   * export {Foo};
   * ```
   *
   * case2: export instance(indirectly).
   *
   * ```javascript
   * class Foo {}
   * let foo = new Foo();
   * export {foo};
   * ```
   *
   * @private
   * @todo support function export.
   */
  _inspectExportNamedDeclaration() {
    const pseudoExportNodes = [];

    for (const exportNode of this._ast.program.body) {
      if (exportNode.type !== 'ExportNamedDeclaration') continue;

      if (exportNode.declaration && exportNode.declaration.type === 'VariableDeclaration') {
        for (const declaration of exportNode.declaration.declarations) {
          if (!declaration.init || declaration.init.type !== 'NewExpression') continue;

          const {classNode, exported} = ASTUtil.findClassDeclarationNode(declaration.init.callee.name, this._ast);
          if (classNode && !exported) {
            const pseudoExportNode = this._copy(exportNode);
            pseudoExportNode.declaration = this._copy(classNode);
            pseudoExportNode.leadingComments = null;
            pseudoExportNodes.push(pseudoExportNode);
            pseudoExportNode.declaration.__PseudoExport__ = true;
            ASTUtil.sanitize(classNode);
          }
        }
        continue;
      }

      for (const specifier of exportNode.specifiers) {
        if (specifier.type !== 'ExportSpecifier') continue;

        let targetClassName = null;
        let pseudoClassExport;

        const varNode = ASTUtil.findVariableDeclarationAndNewExpressionNode(specifier.exported.name, this._ast);
        if (varNode) {
          targetClassName = varNode.declarations[0].init.callee.name;
          pseudoClassExport = true;

          const pseudoExportNode = this._copy(exportNode);
          pseudoExportNode.declaration = this._copy(varNode);
          pseudoExportNode.specifiers = null;
          pseudoExportNodes.push(pseudoExportNode);

          ASTUtil.sanitize(varNode);
        } else {
          targetClassName = specifier.exported.name;
          pseudoClassExport = false;
        }

        const {classNode, exported} = ASTUtil.findClassDeclarationNode(targetClassName, this._ast);
        if (classNode && !exported) {
          const pseudoExportNode = this._copy(exportNode);
          pseudoExportNode.declaration = this._copy(classNode);
          pseudoExportNode.leadingComments = null;
          pseudoExportNode.specifiers = null;
          pseudoExportNode.declaration.__PseudoExport__ = pseudoClassExport;
          pseudoExportNodes.push(pseudoExportNode);
          ASTUtil.sanitize(classNode);
        }

        const functionNode = ASTUtil.findFunctionDeclarationNode(specifier.exported.name, this._ast);
        if (functionNode) {
          const pseudoExportNode = this._copy(exportNode);
          pseudoExportNode.declaration = this._copy(functionNode);
          pseudoExportNode.leadingComments = null;
          pseudoExportNode.specifiers = null;
          ASTUtil.sanitize(functionNode);
          pseudoExportNodes.push(pseudoExportNode);
        }

        const variableNode = ASTUtil.findVariableDeclarationNode(specifier.exported.name, this._ast);
        if (variableNode) {
          const pseudoExportNode = this._copy(exportNode);
          pseudoExportNode.declaration = this._copy(variableNode);
          pseudoExportNode.leadingComments = null;
          pseudoExportNode.specifiers = null;
          ASTUtil.sanitize(variableNode);
          pseudoExportNodes.push(pseudoExportNode);
        }
      }
    }

    this._ast.program.body.push(...pseudoExportNodes);
  }

  /**
   * push node, and factory processes node.
   * @param {ASTNode} node - target node.
   * @param {ASTNode} parentNode - parent node of target node.
   */
  push(node, parentNode) {
    if (node === this._ast) return;

    if (node[already]) return;

    const isLastNodeInParent = this._isLastNodeInParent(node, parentNode);

    node[already] = true;
    Reflect.defineProperty(node, 'parent', {value: parentNode});

    // unwrap export declaration
    if (['ExportDefaultDeclaration', 'ExportNamedDeclaration'].includes(node.type)) {
      parentNode = node;
      node = this._unwrapExportDeclaration(node);
      if (!node) return;
      node[already] = true;
      Reflect.defineProperty(node, 'parent', {value: parentNode});
    }

    // if node has decorators, leading comments is attached to decorators.
    if (node.decorators && node.decorators[0].leadingComments) {
      if (!node.leadingComments || !node.leadingComments.length) {
        node.leadingComments = node.decorators[0].leadingComments;
      }
    }

    let results;
    results = this._traverseComments(parentNode, node, node.leadingComments);
    this._results.push(...results);

    // for trailing comments.
    // traverse with only last node, because prevent duplication of trailing comments.
    if (node.trailingComments && isLastNodeInParent) {
      results = this._traverseComments(parentNode, null, node.trailingComments);
      this._results.push(...results);
    }
  }

  /**
   * traverse comments of node, and create doc object.
   * @param {ASTNode|AST} parentNode - parent of target node.
   * @param {?ASTNode} node - target node.
   * @param {ASTNode[]} comments - comment nodes.
   * @returns {DocObject[]} created doc objects.
   * @private
   */
  _traverseComments(parentNode, node, comments) {
    if (!node) {
      const virtualNode = {};
      Reflect.defineProperty(virtualNode, 'parent', {value: parentNode});
      node = virtualNode;
    }

    if (comments && comments.length) {
      const temp = [];
      for (const comment of comments) {
        if (CommentParser.isESDoc(comment)) temp.push(comment);
      }
      comments = temp;
    } else {
      comments = [];
    }

    if (comments.length === 0) {
      comments = [{type: 'CommentBlock', value: '* @undocument'}];
    }

    const results = [];
    const lastComment = comments[comments.length - 1];
    for (const comment of comments) {
      const tags = CommentParser.parse(comment);

      let doc;
      if (comment === lastComment) {
        doc = this._createDoc(node, tags);
      } else {
        const virtualNode = {};
        Reflect.defineProperty(virtualNode, 'parent', {value: parentNode});
        doc = this._createDoc(virtualNode, tags);
      }

      if (doc) results.push(doc.value);
    }

    return results;
  }

  /**
   * create Doc.
   * @param {ASTNode} node - target node.
   * @param {Tag[]} tags - tags of target node.
   * @returns {AbstractDoc} created Doc.
   * @private
   */
  _createDoc(node, tags) {
    const result = this._decideType(tags, node);
    const type = result.type;
    node = result.node;

    if (!type) return null;

    if (type === 'Class') {
      this._processedClassNodes.push(node);
    }

    let Clazz;
    /* eslint-disable max-statements-per-line */
    switch (type) {
      case 'Class': Clazz = ClassDoc; break;
      case 'Method': Clazz = MethodDoc; break;
      case 'ClassProperty': Clazz = ClassProperty; break;
      case 'Member': Clazz = MemberDoc; break;
      case 'Function': Clazz = FunctionDoc; break;
      case 'Variable': Clazz = VariableDoc; break;
      case 'Assignment': Clazz = AssignmentDoc; break;
      case 'Typedef': Clazz = TypedefDoc; break;
      case 'External': Clazz = ExternalDoc; break;
      default:
        throw new Error(`unexpected type: ${type}`);
    }

    if (!Clazz) return null;
    if (!node.type) node.type = type;

    return new Clazz(this._ast, node, this._pathResolver, tags);
  }

  /**
   * decide Doc type by using tags and node.
   * @param {Tag[]} tags - tags of node.
   * @param {ASTNode} node - target node.
   * @returns {{type: ?string, node: ?ASTNode}} decided type.
   * @private
   */
  _decideType(tags, node) {
    let type = null;
    for (const tag of tags) {
      const tagName = tag.tagName;
      /* eslint-disable default-case */
      switch (tagName) {
        case '@typedef': type = 'Typedef'; break;
        case '@external': type = 'External'; break;
      }
    }

    if (type) return {type, node};

    if (!node) return {type, node};

    /* eslint-disable default-case */
    switch (node.type) {
      case 'ClassDeclaration':
        return this._decideClassDeclarationType(node);
      case 'ClassMethod':
        return this._decideMethodDefinitionType(node);
      case 'ClassProperty':
        return this._decideClassPropertyType(node);
      case 'ExpressionStatement':
        return this._decideExpressionStatementType(node);
      case 'FunctionDeclaration':
        return this._decideFunctionDeclarationType(node);
      case 'FunctionExpression':
        return this._decideFunctionExpressionType(node);
      case 'VariableDeclaration':
        return this._decideVariableType(node);
      case 'AssignmentExpression':
        return this._decideAssignmentType(node);
      case 'ArrowFunctionExpression':
        return this._decideArrowFunctionExpressionType(node);
    }

    return {type: null, node: null};
  }

  /**
   * decide Doc type from class declaration node.
   * @param {ASTNode} node - target node that is class declaration node.
   * @returns {{type: string, node: ASTNode}} decided type.
   * @private
   */
  _decideClassDeclarationType(node) {
    if (!this._isTopDepthInBody(node, this._ast.program.body)) return {type: null, node: null};

    return {type: 'Class', node: node};
  }

  /**
   * decide Doc type from method definition node.
   * @param {ASTNode} node - target node that is method definition node.
   * @returns {{type: ?string, node: ?ASTNode}} decided type.
   * @private
   */
  _decideMethodDefinitionType(node) {
    const classNode = this._findUp(node, ['ClassDeclaration', 'ClassExpression']);
    if (this._processedClassNodes.includes(classNode)) {
      return {type: 'Method', node: node};
    } else {
      logger.w('this method is not in class', node);
      return {type: null, node: null};
    }
  }

  /**
   * decide Doc type from class property node.
   * @param {ASTNode} node - target node that is classs property node.
   * @returns {{type: ?string, node: ?ASTNode}} decided type.
   * @private
   */
  _decideClassPropertyType(node) {
    const classNode = this._findUp(node, ['ClassDeclaration', 'ClassExpression']);
    if (this._processedClassNodes.includes(classNode)) {
      return {type: 'ClassProperty', node: node};
    } else {
      logger.w('this class property is not in class', node);
      return {type: null, node: null};
    }
  }

  /**
   * decide Doc type from function declaration node.
   * @param {ASTNode} node - target node that is function declaration node.
   * @returns {{type: string, node: ASTNode}} decided type.
   * @private
   */
  _decideFunctionDeclarationType(node) {
    if (!this._isTopDepthInBody(node, this._ast.program.body)) return {type: null, node: null};

    return {type: 'Function', node: node};
  }

  /**
   * decide Doc type from function expression node.
   * babylon 6.11.2 judges`export default async function foo(){}` to be `FunctionExpression`.
   * I expect `FunctionDeclaration`. this behavior may be bug of babylon.
   * for now, workaround for it with this method.
   * @param {ASTNode} node - target node that is function expression node.
   * @returns {{type: string, node: ASTNode}} decided type.
   * @private
   * @todo inspect with newer babylon.
   */
  _decideFunctionExpressionType(node) {
    if (!node.async) return {type: null, node: null};
    if (!this._isTopDepthInBody(node, this._ast.program.body)) return {type: null, node: null};

    return {type: 'Function', node: node};
  }

  /**
   * decide Doc type from arrow function expression node.
   * @param {ASTNode} node - target node that is arrow function expression node.
   * @returns {{type: string, node: ASTNode}} decided type.
   * @private
   */
  _decideArrowFunctionExpressionType(node) {
    if (!this._isTopDepthInBody(node, this._ast.program.body)) return {type: null, node: null};

    return {type: 'Function', node: node};
  }

  /**
   * decide Doc type from expression statement node.
   * @param {ASTNode} node - target node that is expression statement node.
   * @returns {{type: ?string, node: ?ASTNode}} decided type.
   * @private
   */
  _decideExpressionStatementType(node) {
    const isTop = this._isTopDepthInBody(node, this._ast.program.body);
    Reflect.defineProperty(node.expression, 'parent', {value: node});
    node = node.expression;
    node[already] = true;

    let innerType;
    let innerNode;

    if (!node.right) return {type: null, node: null};

    switch (node.right.type) {
      case 'FunctionExpression':
        innerType = 'Function';
        break;
      case 'ClassExpression':
        innerType = 'Class';
        break;
      default:
        if (node.left.type === 'MemberExpression' && node.left.object.type === 'ThisExpression') {
          const classNode = this._findUp(node, ['ClassExpression', 'ClassDeclaration']);
          if (!this._processedClassNodes.includes(classNode)) {
            logger.w('this member is not in class.', this._pathResolver.filePath, node);
            return {type: null, node: null};
          }

          return {type: 'Member', node: node};
        } else {
          return {type: null, node: null};
        }
    }

    if (!isTop) return {type: null, node: null};

    /* eslint-disable prefer-const */
    innerNode = node.right;
    innerNode.id = this._copy(node.left.id || node.left.property);
    Reflect.defineProperty(innerNode, 'parent', {value: node});
    innerNode[already] = true;

    return {type: innerType, node: innerNode};
  }

  /**
   * decide Doc type from variable node.
   * @param {ASTNode} node - target node that is variable node.
   * @returns {{type: string, node: ASTNode}} decided type.
   * @private
   */
  _decideVariableType(node) {
    if (!this._isTopDepthInBody(node, this._ast.program.body)) return {type: null, node: null};

    let innerType = null;
    let innerNode = null;

    if (!node.declarations[0].init) return {type: innerType, node: innerNode};

    switch (node.declarations[0].init.type) {
      case 'FunctionExpression':
        innerType = 'Function';
        break;
      case 'ClassExpression':
        innerType = 'Class';
        break;
      case 'ArrowFunctionExpression':
        innerType = 'Function';
        break;
      default:
        return {type: 'Variable', node: node};
    }

    innerNode = node.declarations[0].init;
    innerNode.id = this._copy(node.declarations[0].id);
    Reflect.defineProperty(innerNode, 'parent', {value: node});
    innerNode[already] = true;

    return {type: innerType, node: innerNode};
  }

  /**
   * decide Doc type from assignment node.
   * @param {ASTNode} node - target node that is assignment node.
   * @returns {{type: string, node: ASTNode}} decided type.
   * @private
   */
  _decideAssignmentType(node) {
    if (!this._isTopDepthInBody(node, this._ast.program.body)) return {type: null, node: null};

    let innerType;
    let innerNode;

    switch (node.right.type) {
      case 'FunctionExpression':
        innerType = 'Function';
        break;
      case 'ClassExpression':
        innerType = 'Class';
        break;
      default:
        return {type: 'Assignment', node: node};
    }

    /* eslint-disable prefer-const */
    innerNode = node.right;
    innerNode.id = this._copy(node.left.id || node.left.property);
    Reflect.defineProperty(innerNode, 'parent', {value: node});
    innerNode[already] = true;

    return {type: innerType, node: innerNode};
  }

  /**
   * unwrap exported node.
   * @param {ASTNode} node - target node that is export declaration node.
   * @returns {ASTNode|null} unwrapped child node of exported node.
   * @private
   */
  _unwrapExportDeclaration(node) {
    // e.g. `export A from './A.js'` has not declaration
    if (!node.declaration) return null;

    const exportedASTNode = node.declaration;
    if (!exportedASTNode.leadingComments) exportedASTNode.leadingComments = [];
    exportedASTNode.leadingComments.push(...node.leadingComments || []);

    if (!exportedASTNode.trailingComments) exportedASTNode.trailingComments = [];
    exportedASTNode.trailingComments.push(...node.trailingComments || []);

    return exportedASTNode;
  }

  /**
   * judge node is last in parent.
   * @param {ASTNode} node - target node.
   * @param {ASTNode} parentNode - target parent node.
   * @returns {boolean} if true, the node is last in parent.
   * @private
   */
  _isLastNodeInParent(node, parentNode) {
    if (parentNode && parentNode.body) {
      const lastNode = parentNode.body[parentNode.body.length - 1];
      return node === lastNode;
    }

    return false;
  }

  /**
   * judge node is top in body.
   * @param {ASTNode} node - target node.
   * @param {ASTNode[]} body - target body node.
   * @returns {boolean} if true, the node is top in body.
   * @private
   */
  _isTopDepthInBody(node, body) {
    if (!body) return false;
    if (!Array.isArray(body)) return false;

    const parentNode = node.parent;
    if (['ExportDefaultDeclaration', 'ExportNamedDeclaration'].includes(parentNode.type)) {
      node = parentNode;
    }

    for (const _node of body) {
      if (node === _node) return true;
    }
    return false;
  }

  /**
   * deep copy object.
   * @param {Object} obj - target object.
   * @return {Object} copied object.
   * @private
   */
  _copy(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  /**
   * find node while goes up.
   * @param {ASTNode} node - start node.
   * @param {string[]} types - ASTNode types.
   * @returns {ASTNode|null} found first node.
   * @private
   */
  _findUp(node, types) {
    let parent = node.parent;
    while (parent) {
      if (types.includes(parent.type)) return parent;
      parent = parent.parent;
    }

    return null;
  }
}
static parse(commentNode) {
  if (!this.isESDoc(commentNode)) return [];

  let comment = commentNode.value;

  // TODO: refactor
  comment = comment.replace(/\r\n/gm, '\n'); // for windows
  comment = comment.replace(/^[\t ]*/gm, ''); // remove line head space
  comment = comment.replace(/^\*[\t ]?/, ''); // remove first '*'
  comment = comment.replace(/[\t ]$/, ''); // remove last space
  comment = comment.replace(/^\*[\t ]?/gm, ''); // remove line head '*'
  if (comment.charAt(0) !== '@') comment = `@desc ${comment}`; // auto insert @desc
  comment = comment.replace(/[\t ]*$/, ''); // remove tail space.
  comment = comment.replace(/```[\s\S]*?```/g, (match) => match.replace(/@/g, '\\ESCAPED_AT\\')); // escape code in descriptions
  comment = comment.replace(/^[\t ]*(@\w+)$/gm, '$1 \\TRUE'); // auto insert tag text to non-text tag (e.g. @interface)
  comment = comment.replace(/^[\t ]*(@\w+)[\t ](.*)/gm, '\\Z$1\\Z$2'); // insert separator (\\Z@tag\\Ztext)
  const lines = comment.split('\\Z');

  let tagName = '';
  let tagValue = '';
  const tags = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.charAt(0) === '@') {
      tagName = line;
      const nextLine = lines[i + 1];
      if (nextLine.charAt(0) === '@') {
        tagValue = '';
      } else {
        tagValue = nextLine;
        i++;
      }
      tagValue = tagValue.replace('\\TRUE', '')
        .replace(/\\ESCAPED_AT\\/g, '@')
        .replace(/^\n/, '')
        .replace(/\n*$/, '');
      tags.push({tagName, tagValue});
    }
  }
  return tags;
}

/**
 * parse node to tags.
 * @param {ASTNode} node - node.
 * @returns {{tags: Tag[], commentNode: CommentNode}} parsed comment.
 */
static parseFromNode(node) {
  if (!node.leadingComments) node.leadingComments = [{type: 'CommentBlock', value: ''}];
  const commentNode = node.leadingComments[node.leadingComments.length - 1];
  const tags = this.parse(commentNode);

  return {tags, commentNode};
}

/**
 * judge doc comment or not.
 * @param {ASTNode} commentNode - comment node.
 * @returns {boolean} if true, this comment node is doc comment.
 */
static isESDoc(commentNode) {
  if (commentNode.type !== 'CommentBlock') return false;
  return commentNode.value.charAt(0) === '*';
}

/**
 * build comment from tags
 * @param {Tag[]} tags
 * @returns {string} block comment value.
 */
static buildComment(tags) {
  return tags.reduce((comment, tag) => {
    const line = tag.tagValue.replace(/\n/g, '\n * ');
    return `${comment} * ${tag.tagName} \n * ${line} \n`;
  }, '*\n');
}
}
const callInfo = {handlerNames: {}, usedParser: false};
exports.callInfo = callInfo;

let originalParser;
function parser(code) {
  callInfo.usedParser = true;
  return originalParser(code);
}

exports.onStart = function(ev) {
  callInfo.handlerNames.onStart = true;
  callInfo.option = ev.data.option;
};

exports.onHandleConfig = function(ev) {
  callInfo.handlerNames.onHandleConfig = true;
};

exports.onHandleCode = function(ev) {
  callInfo.handlerNames.onHandleCode = true;

  if (ev.data.filePath.includes('EmptyForPlugin.js')) {
    ev.data.code = 'export class EmptyForPlugin {}';
  }
};

exports.onHandleCodeParser = function(ev) {
  callInfo.handlerNames.onHandleCodeParser = true;
  originalParser = ev.data.parser;
  ev.data.parser = parser;
};

exports.onHandleAST = function(ev) {
  callInfo.handlerNames.onHandleAST = true;

  if (ev.data.filePath.includes('EmptyForPlugin.js')) {
    ev.data.ast.program.body[0].declaration.id.name += '_Modified1';
  }
};

exports.onHandleDocs = function(ev) {
  callInfo.handlerNames.onHandleDocs = true;

  const doc = ev.data.docs.find((doc) => doc.name === 'EmptyForPlugin_Modified1');
  doc.longname += '_Modified2';
  doc.name += '_Modified2';
};

exports.onPublish = function(ev) {
  callInfo.handlerNames.onPublish = true;

  const docs = JSON.parse(ev.data.readFile('index.json'));
  const doc = docs.find(doc => doc.name === 'EmptyForPlugin_Modified1_Modified2');
  ev.data.writeFile('index.md', `${doc.name}\n made by MyPlugin1`);
};

exports.onHandleContent = function(ev) {
  callInfo.handlerNames.onHandleContent = true;
  ev.data.content = ev.data.content.replace('MyPlugin1', 'MyPlugin1_Modified');
};

exports.onComplete = function(ev) {
  callInfo.handlerNames.onComplete = true;
};
import assert from 'assert';
import fs from 'fs';
import {find} from '../util';

describe('test/plugin/MyPlugin1:', ()=>{
  it('calls handlers', ()=>{
    const callInfo = require('./MyPlugin1').callInfo;
    assert.deepEqual(callInfo.handlerNames, {
      onStart: true,
      onHandleConfig: true,
      onHandleCode: true,
      onHandleCodeParser: true,
      onHandleAST: true,
      onHandleDocs: true,
      onPublish: true,
      onHandleContent: true,
      onComplete: true
    });

    assert.equal(callInfo.usedParser, true);
  });

  it('modified input', ()=>{
    const doc = find('longname', /EmptyForPlugin_Modified1_Modified2$/);
    assert.equal(doc.kind, 'class');
  });

  it('output', ()=>{
    const content = fs.readFileSync('./test/integration-test/out/index.md').toString();
    assert(content.includes('EmptyForPlugin_Modified1_Modified2'));
    assert(content.includes('made by MyPlugin1_Modified'));
  });
});
export class TestDuplication {
  constructor() {
    /** @type {number} */
    this.member = 1;

    /** @type {string} */
    this.member = 'b';

    /** @type {boolean} */
    this.member = true;
  }
}
import assert from 'assert';

describe('test/_Misc/Duplication:', ()=>{
  it('does not duplication', ()=>{
    const docs = global.docs.filter((doc) => doc.longname === 'src/_Misc/Duplication.js~TestDuplication#member');
    assert.equal(docs.length, 1);

    const doc = docs[0];
    assert.deepEqual(doc.type, {
      "nullable": null,
      "types": [
        "number"
      ],
      "spread": false,
      "description": null
    });
  });
});
import assert from 'assert';
import {find} from '../../util';

describe('test/_Misc/Exclude:', ()=>{
  it('not exist', ()=>{
    const doc = find('longname', 'src/_Misc/Exclude.js~TestExclude');
    assert.equal(doc, null);
  });
});
import assert from 'assert';
import InvalidCodeLogger from '../../../../src/Util/InvalidCodeLogger';

describe('test/_Misc/InvalidSyntax:', ()=>{
  it('is invalid', ()=>{
    assert.equal(InvalidCodeLogger._logs.length, 2);

    assert(InvalidCodeLogger._logs[0].filePath.includes('test/integration-test/src/_Misc/InvalidSyntaxCode.js'));
    assert.deepEqual(InvalidCodeLogger._logs[0].log, [1, 2]);

    assert(InvalidCodeLogger._logs[1].filePath.includes('test/integration-test/src/_Misc/InvalidSyntaxDoc.js'));
    assert.deepEqual(InvalidCodeLogger._logs[1].log, [1, 4]);
  });
});
import assert from 'assert';
import fs from 'fs';
import path from 'path';

describe('config outputAST:', ()=>{
  it('does not generate AST', ()=>{
    const outDir = fs.readdirSync(path.resolve(__dirname, '../../out'));
    assert(outDir.includes('ast') === false)
  });
});
import {idTodotoolsofHuy} from "src/type/idTodotoolsofHuy.types";
import {BaseStoreManager} from "./BaseStoreManager"
  interface TodoStoreofHuy {
    idTodotoolsofHuy: TodoStoreofHuy[];
  }
  const initialState: TodoStoreofHuy = {
    todos: [],
  }
  class TodoStoreManager extends BaseStoreManager<TodoStore>{
    addTodoHuy(newFileTodo: idTodotoolsofHuy){
      const currentTodoList = this.get("todos");
    }
      const newTodoList = [...currentTodoList, newTodo];
    this.set({todos: new})  
  }
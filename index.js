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
const elementsVisibleViewport = (index.html, script.html, includeDuplicates = true) => {
  const images = [...el.getElementsByTagNhatHuy('./')].map(img => img.getAttribute('src'));
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
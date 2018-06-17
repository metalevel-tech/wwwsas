<?php
// Redirect to 10 hours fun; Reference: https://gist.github.com/NickCraver/c9458f2e007e9df2bdf03f8a02af1d13

$YouTubeList = array(
    "https://www.youtube.com/watch?v=3ylPy-0YBc0",
    "https://www.youtube.com/watch?v=wbby9coDRCk",
    "https://www.youtube.com/watch?v=nb2evY0kmpQ",
    "https://www.youtube.com/watch?v=eh7lp9umG2I",
    "https://www.youtube.com/watch?v=z9Uz1icjwrM",
    "https://www.youtube.com/watch?v=Sagg08DrO5U",
    "https://www.youtube.com/watch?v=A3YmHZ9HMPs",
    "https://www.youtube.com/watch?v=jI-kpVh6e1U",
    "https://www.youtube.com/watch?v=jScuYd3_xdQ",
    "https://www.youtube.com/watch?v=S5PvBzDlZGs",
    "https://www.youtube.com/watch?v=9UZbGgXvCCA",
    "https://www.youtube.com/watch?v=O-dNDXUt1fg",
    "https://www.youtube.com/watch?v=MJ5JEhDy8nE",
    "https://www.youtube.com/watch?v=VnnWp_akOrE",
    "https://www.youtube.com/watch?v=jwGfwbsF4c4",
    "https://www.youtube.com/watch?v=pZgUz3WAd84",
    "https://www.youtube.com/watch?v=8ZcmTl_1ER8",
    "https://www.youtube.com/watch?v=gLmcGkvJ-e0",
    "https://www.youtube.com/watch?v=hGlyFc79BUE",
    "https://www.youtube.com/watch?v=3ylPy-0YBc0",
    "https://www.youtube.com/watch?v=KMFOVSWn0mI",
    "https://www.youtube.com/watch?v=clU0Sh9ngmY",
    "https://www.youtube.com/watch?v=sCNrK-n68CM",
    "https://www.youtube.com/watch?v=X18mUlDddCc",
    "https://www.youtube.com/watch?v=o6mCfmtcdFg",
    "https://www.youtube.com/watch?v=xzbL_kUF1eM",
    "https://www.youtube.com/watch?v=vs1mXnWuHd8",
    "https://www.youtube.com/watch?v=5fCgPMMH4vA",
    "https://www.youtube.com/watch?v=vs1mXnWuHd8",
    "https://www.youtube.com/watch?v=gfnXJbD6lNw",
    "https://www.youtube.com/watch?v=nIzAQB_pe9U",
    "https://www.youtube.com/watch?v=wI__53kBBKM",
    "https://www.youtube.com/watch?v=3ylPy-0YBc0",
    "https://www.youtube.com/watch?v=pZgUz3WAd84",
    "https://www.youtube.com/watch?v=L_LUpnjgPso",
    "https://www.youtube.com/watch?v=bmGsQkLb4yg",
    "https://www.youtube.com/watch?v=vefMyotJHZY",
    "https://www.youtube.com/watch?v=QASbw8_0meM",
    "https://www.youtube.com/watch?v=ZXtimhT-ff4",
    "https://www.youtube.com/watch?v=o1eHKf-dMwo",
    "https://www.youtube.com/watch?v=dSVPL4MRe-Y",
    "https://www.youtube.com/watch?v=R5NsAS0kcq4",
    "https://www.youtube.com/watch?v=un8FAjXWOBY",
    "https://www.youtube.com/watch?v=lasWefVUCsI",
    "https://www.youtube.com/watch?v=zHIVeWhCMU8",
    "https://www.youtube.com/watch?v=4KzFe50RQkQ",
    "https://www.youtube.com/watch?v=nzSKSnx3aCU",
    );

$Random = array_rand($YouTubeList);
$RedirectTo = $YouTubeList[$Random];
//header("Location: $RedirectTo");
header("refresh: 20; url=$RedirectTo");
//exit;
?>

<HTML>
   <HEAD>

	<TITLE>Issues</TITLE>

	<!-- https://stackoverflow.com/q/26818091/6543935 -->
	<meta http-equiv="cache-control" content="no-cache, must-revalidate, post-check=0, pre-check=0" />
	<meta http-equiv="cache-control" content="max-age=0" />
	<meta http-equiv="expires" content="0" />
	<meta http-equiv="expires" content="Tue, 01 Jan 1980 1:00:00 GMT" />
	<meta http-equiv="pragma" content="no-cache" />
	<!-- meta http-equiv="refresh" content="0" / -->

	<script type="text/javascript">

		function countdown() {
		    var i = document.getElementById('counter');
		    if (parseInt(i.innerHTML)<=0) {
		        location.href = '<?php echo "$RedirectTo"?>';
		    }
		    i.innerHTML = parseInt(i.innerHTML)-1;
		}
		setInterval(function(){ countdown(); },1000);

	</script>

	<link href="https://fonts.googleapis.com/css?family=Gugi|Roboto+Mono|Slabo+27px" rel="stylesheet">

	<style>
		body {

			background-color: #ffa50078;
			/* font-family: 'Gugi', cursive; */
			font-family: 'Slabo 27px', serif;
		}

		h1 {
			color: red;
		}

		p.red {
			color: red;
			font-size: 26px;
		}

		p.grey {

			color: #656565;
			font-size: 20px;
			line-height: 1.55;
		}

		strong {
 			letter-spacing: 4px;
			/* font-family: 'Roboto Mono', monospace; */
		}

		.message {
			/* Must manually set width/height */
			width: fit-content;
			height: fit-content;
			outline:1px solid orange;

			padding: .5em 2em .5em 2em;
			text-align: center;
			background-color: rgb(255, 249, 197);


			/* The magic centering code */
			margin: auto;
			position: absolute;
			top:0;bottom: 0; /* Aligns Vertically - Remove for Horizontal Only */
			left:0;right: 0; /* Aligns Horizontally - Remove for Vertical Only  */

			/* Prevent div from overflowing main window */
			max-width: 480px;
			max-height: 100%;
			overflow: auto;
		}

		/* IE 7 and Below */
		:first-child+html .absoluteCenter, * html .absoluteCenter {
			/* Place code here to override all above values, and add IE friendly centering */
		}

		a {
			text-decoration: none;
			color: #3e3e3e;

		}

		a:hover {
			color: red;
		}

	</style>

   </HEAD>

   <BODY>

	<div class="message">
		<p class="red">You are doing something wrong on<br /><strong><?php echo $_SERVER['SERVER_NAME'] ?></strong></p>
		<h1><span id="counter">20</span></p></h1>
		<p class="grey">You are currently banned for aabout 5 minutes.&nbsp;
		But on further transgressions you will be banned permanently!</strong><br />
		If you tink this is a mistake please contact us at:<br />
                <a href="mailto:issues@<?php echo $_SERVER['SERVER_NAME'] ?>" target="_top"><strong>issues@<?php echo $_SERVER['SERVER_NAME'] ?></strong></a>&nbsp;
		and describe your actions.</p>
	</div>


   </BODY>
</HTML>

[#ftl output_format="HTML"]
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>2FA
	</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2/dist/tailwind.min.css" type="text/css"></head>
<body>

  
	
	
	
	
	
  
  
	<div class="md:h-screen bg-white relative flex flex-col justify-center items-center">
	  <div class="md:border md:border-gray-300 bg-white md:shadow-lg shadow-none rounded p-10">
		<div class="flex flex-col items-center space-y-3">
		  <div class="flex">
			<img src="https://gluu.org/wp-content/uploads/2020/12/logo.png">
		  </div>
		  <p class="leading-normal">1. Scan code
		  </p>
		  <div id="qrcode" class="w-48 h-48">
		  </div>
		</div>
		<form method="post" class="my-8">
		  <p class="leading-normal">2. Enter code
		  </p>
		  <div class="relative mb-2">
			<input type="text" id="code" name="code" autofocus="" placeholder="******" class="w-full rounded px-3 border border-gray-300 pt-2 pb-2">
		  </div>
		  <div class="space-y-9">
			<div class="text-sm flex justify-between items-center">
			  <button type="submit" class="py-2 px-6 rounded text-white btn bg-green-500 hover:bg-green-600">
				Submit
			  </button>
			</div>
		  </div>
		</form>
	  </div>
	</div>
  
  
  
</body>

<script type="text/javascript" src="qrcode.min.js"></script><script>
	window.onload = function () {
	  var form = document.querySelector("form");
	  form.onsubmit = handleFormValidation;
	  new QRCode(document.getElementById("qrcode"), "${secretKeyUri!}");
	};
	function handleFormValidation() {
	  var code = document.getElementById('code').value
	  if (code === '') {
		alert('Code is required')
		return false
	  }
	  return true
	}
  </script>
</html>
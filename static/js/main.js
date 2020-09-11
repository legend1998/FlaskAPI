
var scene = document.getElementById('scene');
var parallaxInstance = new Parallax(scene);

var front = document.getElementById('front');
var parallaxInstance2 = new Parallax(front);
$(document).ready(function(){
    
   $(window).resize(function(){
       if($(window).width()<700){
           parallaxInstance2.disable();
           parallaxInstance.disable();
       }
       else{
        parallaxInstance2.enable();
        parallaxInstance.enable();
       }
   })
})
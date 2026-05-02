const canvas = document.querySelector("#canvas");
const rec = document.querySelector("#rec");
const ball = document.querySelector("#ball");
const h1 = document.querySelector("#h1");
const btn = document.querySelector("#btn");

function moveRec(){
    rec.focus();
        let steps = 10;
        let counter = {
            ArrowLeft: 0,
            ArrowRight: 0
        };
       if(!rec.style.left){
        rec.style.left = "300px";
       }
        document.addEventListener("keydown", (event) => { 
            const key = event.key;
            let left = parseInt(rec.style.left);
            if(key === "ArrowLeft" && left > 0){
                counter.ArrowLeft++;
                rec.style.left = `${left - steps}px`;
            }
            else if(key === "ArrowRight" && left < 700){
                counter.ArrowRight++;
                rec.style.left = `${left + steps}px`;
            }
            else{
                // console.log("Invalid Key")
            }

        });
}
function load(){
    window.location.reload();
}
function ballmove(){
    const speed = 5;
    let angle = 45 * Math.PI / 180;
    console.log(speed)
    console.log(angle)
    let ballx = Math.cos(angle) * speed;
    let bally = Math.sin(angle) * speed;
    let ballLeft = parseInt(ball.style.left || "0");
    let ballTop = parseInt(ball.style.top || "0");
    function updateBall(){
        ballLeft += ballx;
        ballTop += bally;
        const ballRight = ballLeft + ball.offsetWidth;
        const ballBottom = ballTop + ball.offsetHeight;
        if(ballLeft < 0 || ballLeft > canvas.clientWidth - ball.clientWidth){
            ballx = -ballx;
        }
        else if(ballTop < 0 || ballTop > canvas.clientHeight - ball.clientHeight){
            bally = -bally;
        }
        const recLeft = rec.offsetLeft;
        const recTop = rec.offsetTop;
        const recWidth = rec.offsetWidth;
        const recHeight = rec.offsetHeight;
        const recRight = recLeft + recWidth;
        const recBottom = recTop + recHeight;
        if(ballBottom >= recTop && ballTop <= recBottom && ballRight >= recLeft && ballLeft <= recRight){
            bally = -bally;
            ballTop = recTop - ball.offsetHeight;
        }
        
        if(ballBottom > canvas.clientHeight){
            // console.log("Game Over");
            h1.style.display = "block";
            btn.style.display = "block";
            setTimeout(() => {
                rec.style.display = "none";
                ball.style.display = "none";
             }, 1000)
            
            // let gameover = true;
            return;
            // setTimeout(() => {
            //     window.location.reload();
            // }, 5000)
        }

        ball.style.left = (`${ballLeft}px`);
        ball.style.top = (`${ballTop}px`);
        requestAnimationFrame(updateBall);

    }
    updateBall();
}
moveRec();
ballmove();
// console.log("5")
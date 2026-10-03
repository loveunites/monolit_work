const form=document.querySelector('#request-form');
form?.addEventListener('submit',(event)=>{event.preventDefault();const status=form.querySelector('.form-status');status.textContent='Спасибо! Прораб свяжется с вами в ближайшее время.';form.reset();});

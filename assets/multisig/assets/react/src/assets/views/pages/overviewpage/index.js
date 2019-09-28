import React, {Component} from 'react'
import Style from './style.css'

class OverviewPage extends Component {
    constructor (props) {
        super(props);
    }

    render(){ return(
    	<div className={`Overview ${Style.page}`}>
	        <div className={`Overview ${Style.logo}`}>
	        </div>
	        <p className={`Overview ${Style.title}`}> 
	        	<span className={`Overview ${Style.word}`}>
	        		DECENTRALIZED
	        	</span>
	        	<span className={`Overview ${Style.word}`}>
	        		ANONYMOUS
	        	</span>
	        	<span className={`Overview ${Style.word}`}>
	        		PAYMENT
	        	</span>
	        	<span className={`Overview ${Style.word}`}>
	        		SYSTEM
	        	</span> 	 	 	 
	        </p>
	    </div>
    )}
}

//OverviewPage.proptypes = {  }

export default OverviewPage
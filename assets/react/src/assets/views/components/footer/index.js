import React, { Component } from 'react'
import PropTypes from 'prop-types'
import Style from './style.css'

import ListBox from 'Components/listbox'

class Footer extends Component {
    constructor(props) {
        super(props);
        this.state = {
            MasterNode: (props.data.data && props.data.data['MASTER NODES'] && props.data.data['MASTER NODES'][0]) || 0,
            Node: (props.data.data && props.data.data['NODES'] && props.data.data['NODES'][0]) || 0,
        }

        this.Links = {
            headers: ["Company", "Learn", "Contact Us"],
            '0': [
                <a key="About" href='https://officialdapscoin.com/roadmap/' target="_blank">About</a>,
                <a key="Team" href='https://officialdapscoin.com/team/' target="_blank">Team</a>,
                // <a href='google.com'>Careers</a>,
            ],
            "1": [
                <a key="Getting Started" href='https://officialdapscoin.com/roadmap/' target="_blank">Getting Started</a>,
                <a key="DAPS Blog" href='https://officialdapscoin.com/daps-project-blog/' target="_blank">DAPS Blog</a>,
                <a key="What is DAPS" href='https://officialdapscoin.com/info/' target="_blank">What is DAPS?</a>,
            ],
            "2": [
                // <a href='google.com'>Press</a>,
                <a key="Support" href='https://officialdapscoin.com/contact/' target="_blank">Support</a>,
                // <a href='google.com'>Status</a>,
            ],
            // "3": [<a href='google.com'>Local</a>],
        }
        this.SocialLinks = {
            "headers": [],
            "0": [
                <a key="discord" href='https://officialdapscoin.com/discord' id='discordlink' className='SocialLink' target="_blank" ><div id='discord' /></a>,
                <a key="facebook" href='https://www.facebook.com/dapscoinofficial/' id='facebooklink' className='SocialLink' target="_blank" ><div id='facebook' /></a>,
                <a key="reddit" href='https://www.reddit.com/r/DAPSCoin/' id='redditlink' className='SocialLink' target="_blank"><div id='reddit' /></a>,
                <a key="telegram" href='https://t.me/dapscoin' id='telegramlink' className='SocialLink' target="_blank" ><div id='telegram' /></a>,
                <a key="linkedin" href='https://www.linkedin.com/company/daps-coin/' id='linkedinlink' className='SocialLink' target="_blank"><div id='linkedin' /></a>,
                <a key="twitter" href='https://twitter.com/DAPScoin' id='twitterlink' className='SocialLink' target="_blank" ><div id='twitter' /></a>,
            ]
        }
    }

    componentWillReceiveProps(props) {
        this.setState({
            MasterNode: (props.data.data && props.data.data['MASTER NODES'] && props.data.data['MASTER NODES'][0]) || 0,
            Node: (props.data.data && props.data.data['NODES'] && props.data.data['NODES'][0]) || 0,
        });
    }

    render() {
        let masterPercent = 100 * parseInt(this.state.MasterNode) / parseInt(this.state.Node);
        if (this.state.Node == 0)
            return (<div className="Footer">
                        <div id="FooterInfo">
                        <ListBox id="FooterLinks" data={this.Links}/>
                        <div id="SocialLinksContainer">{this.SocialLinks[0]}</div>
                        <div id="CR">
                            <h2>Version: Beta</h2>
                            <br />
                            <h3>&copy; 2019 The DAPS Project All Rights Reserved</h3>
                        </div>
                    </div>
                   </div>
            );
        
        let stakingPercent = 100 - masterPercent;
        let stakingStyle = {
            width: String(stakingPercent) + '%'
        };
        let masterStyle = {
            width: String(masterPercent) + '%'
        };

        return (<div className="Footer">
            <div id="FooterBar" className={`${Style.FooterBar}`}>
                <div id="RewardState" className={`${Style.RewardState}`}>
                    <div id="StakingState" className={`${Style.StakingState}`} style={stakingStyle}>
                        <span id="StakingTitle" className={`${Style.StakingTitle}`}>
                            STAKING NODES
                        </span>
                        <span id="StakingCount" className={`${Style.StakingCount}`}>
                            {this.state.Node - this.state.MasterNode}
                        </span>
                        <span id="StakingPercent" className={`${Style.StakingPercent}`}>
                            {String(stakingPercent.toFixed(4)) + '%'}
                        </span>
                    </div>
                    <div id="MasterState" className={`${Style.MasterState}`} style={masterStyle}>
                        <span id="MasterPercent" className={`${Style.MasterPercent}`}>
                            {String(masterPercent.toFixed(4)) + '%'}
                        </span>
                        <span id="MasterCount" className={`${Style.MasterCount}`}>
                            {this.state.MasterNode}
                        </span>
                        <span id="MasterTitle" className={`${Style.MasterTitle}`}>
                            MASTER NODES
                        </span>
                    </div>
                </div>
            </div>
            <div id="FooterInfo">
                <ListBox id="FooterLinks" data={this.Links}/>
                <div id="SocialLinksContainer">{this.SocialLinks[0]}</div>
                <div id="CR">
                    <h2>Version: Beta</h2>
                    <br />
                    <h3>&copy; 2019 The DAPS Project All Rights Reserved</h3>
                </div>
            </div>
        </div>
        )
    }
}

export default Footer;

import React, { Component } from "react";
import { Route, Switch, browserHistory, Link } from 'react-router-dom';
import PropTypes from "prop-types";
import merge from "deepmerge"

import Actions from 'Actions'

// import DetailPage from 'Pages/detailpage'
import BlockDetail from 'Pages/blockdetail'
import Genesis from 'Pages/genesis'
import TxDetail from 'Pages/txdetail'
import ListPage from 'Pages/listpage'
import OverviewPage from 'Pages/overviewpage'
import StatusBar from 'Pages/statusbar'

import NavBar from 'Components/navbar'
import Footer from 'Components/footer'
import SearchBar from 'Components/searchbar'

import 'Stylesheets/main.css'
import Style from 'Stylesheets/app.css'

const route = "/explorer/";

const pagesize = 20;

class BlockExplorer extends Component {
  constructor(props) {
    super(props);
    // let pageLinks = this.getListPageLinks()    
    this.state = {
      lib: new Map(),
      path: '', pageindex: 0,
      listpageData: {},
      pagesize: pagesize,
      param: '', search: '', type: '', typemin: '', prim: '',
      blockStatus: {}, netStatus: {},
      isTouch: this.mobileAndTabletcheck(),
    };
    // Promise.resolve(Actions.getTxCount()).then(count => this.setState({ txCount: count }))
    // setInterval(() => Promise.resolve(Actions.getTxCount()).then(count => this.setState({ txCount: count })), 5000)
    // Promise.resolve(Actions.getBlockCount()).then(count => this.setState({ blockCount: count }))
    // setInterval(() => Promise.resolve(Actions.getBlockCount()).then(count => this.setState({ blockCount: count })), 5000)
  }

  mobileAndTabletcheck() { //function from detectmobilebrowsers.com via https://stackoverflow.com/questions/11381673/detecting-a-mobile-browser
    var check = false;
    (function (a) { if (/(android|bb\d+|meego).+mobile|avantgo|bada\/|blackberry|blazer|compal|elaine|fennec|hiptop|iemobile|ip(hone|od)|iris|kindle|lge |maemo|midp|mmp|mobile.+firefox|netfront|opera m(ob|in)i|palm( os)?|phone|p(ixi|re)\/|plucker|pocket|psp|series(4|6)0|symbian|treo|up\.(browser|link)|vodafone|wap|windows ce|xda|xiino|android|ipad|playbook|silk/i.test(a) || /1207|6310|6590|3gso|4thp|50[1-6]i|770s|802s|a wa|abac|ac(er|oo|s\-)|ai(ko|rn)|al(av|ca|co)|amoi|an(ex|ny|yw)|aptu|ar(ch|go)|as(te|us)|attw|au(di|\-m|r |s )|avan|be(ck|ll|nq)|bi(lb|rd)|bl(ac|az)|br(e|v)w|bumb|bw\-(n|u)|c55\/|capi|ccwa|cdm\-|cell|chtm|cldc|cmd\-|co(mp|nd)|craw|da(it|ll|ng)|dbte|dc\-s|devi|dica|dmob|do(c|p)o|ds(12|\-d)|el(49|ai)|em(l2|ul)|er(ic|k0)|esl8|ez([4-7]0|os|wa|ze)|fetc|fly(\-|_)|g1 u|g560|gene|gf\-5|g\-mo|go(\.w|od)|gr(ad|un)|haie|hcit|hd\-(m|p|t)|hei\-|hi(pt|ta)|hp( i|ip)|hs\-c|ht(c(\-| |_|a|g|p|s|t)|tp)|hu(aw|tc)|i\-(20|go|ma)|i230|iac( |\-|\/)|ibro|idea|ig01|ikom|im1k|inno|ipaq|iris|ja(t|v)a|jbro|jemu|jigs|kddi|keji|kgt( |\/)|klon|kpt |kwc\-|kyo(c|k)|le(no|xi)|lg( g|\/(k|l|u)|50|54|\-[a-w])|libw|lynx|m1\-w|m3ga|m50\/|ma(te|ui|xo)|mc(01|21|ca)|m\-cr|me(rc|ri)|mi(o8|oa|ts)|mmef|mo(01|02|bi|de|do|t(\-| |o|v)|zz)|mt(50|p1|v )|mwbp|mywa|n10[0-2]|n20[2-3]|n30(0|2)|n50(0|2|5)|n7(0(0|1)|10)|ne((c|m)\-|on|tf|wf|wg|wt)|nok(6|i)|nzph|o2im|op(ti|wv)|oran|owg1|p800|pan(a|d|t)|pdxg|pg(13|\-([1-8]|c))|phil|pire|pl(ay|uc)|pn\-2|po(ck|rt|se)|prox|psio|pt\-g|qa\-a|qc(07|12|21|32|60|\-[2-7]|i\-)|qtek|r380|r600|raks|rim9|ro(ve|zo)|s55\/|sa(ge|ma|mm|ms|ny|va)|sc(01|h\-|oo|p\-)|sdk\/|se(c(\-|0|1)|47|mc|nd|ri)|sgh\-|shar|sie(\-|m)|sk\-0|sl(45|id)|sm(al|ar|b3|it|t5)|so(ft|ny)|sp(01|h\-|v\-|v )|sy(01|mb)|t2(18|50)|t6(00|10|18)|ta(gt|lk)|tcl\-|tdg\-|tel(i|m)|tim\-|t\-mo|to(pl|sh)|ts(70|m\-|m3|m5)|tx\-9|up(\.b|g1|si)|utst|v400|v750|veri|vi(rg|te)|vk(40|5[0-3]|\-v)|vm40|voda|vulc|vx(52|53|60|61|70|80|81|83|85|98)|w3c(\-| )|webc|whit|wi(g |nc|nw)|wmlb|wonu|x700|yas\-|your|zeto|zte\-/i.test(a.substr(0, 4))) check = true; })(navigator.userAgent || navigator.vendor || window.opera);
    return check;
  }

  async getListPageLinks() {
    try {
      if (this.state) {
        let index = this.state.pageindex
        let totalCnt = 0;
        if (this.state.type.toLowerCase().indexOf('transaction') >= 0)
          totalCnt = await Actions.getTxCount();
        else if (this.state.type.toLowerCase().indexOf('poablock') >= 0)
          totalCnt = await Actions.getPoaBlockCount();
        else if (this.state.type.toLowerCase().indexOf('posblock') >= 0)
          totalCnt = await Actions.getPosBlockCount();
        else
          totalCnt = await Actions.getBlockCount();

        let lastpage = Math.ceil(totalCnt / this.state.pagesize)
        let routearray = [-2, -1, 0, 1, 2]
          , rshift = ((index + routearray[0]) <= 0) ? Math.abs(index + routearray[0]) + 1 : 0
          , lshift = ((index + routearray[4]) >= lastpage) ? Math.abs(lastpage - (index + routearray[4])) : 0
        routearray = routearray.map(i => (i + rshift - lshift))
        let sort = (this.state.type.toLowerCase().indexOf('block') != -1) ? 'block' : 'tx';
        sort = (sort == 'block') ? 'height' : 'blockindex'
        this.state.pageLinks = (<div>
            {(index > 1) ? <Link to={`/explorer/${this.state.type}/?limit=${pagesize}&page=${index - 1}`}>Prev</Link> : ''}
            {(index > 1) ? <span>   ...   </span> : ''}
            {(index > 4) ? [1, 2, 3].map(i => <Link key={i} to={`/explorer/${this.state.type}/?limit=${pagesize}&page=${i}`}>{i}  </Link>) : ''}
            {(index > 4) ? <span>   ...   </span> : ''}
            {routearray.map(i => {
              if (index + i >= 0 && index + i <= lastpage)
                return <Link key={i} to={`/explorer/${this.state.type}/?limit=${pagesize}&page=${index + i}`}>{index + i}  </Link>
            })}
            {(index < lastpage - 4) ? <span>   ...   </span> : ''}
            {(index < lastpage - 4) ? [2, 1, 0].map(i => <Link key={lastpage - i} to={`/explorer/${this.state.type}/?limit=${pagesize}&page=${lastpage - i}`}>{lastpage - i}  </Link>) : ''}
            {(index < lastpage) ? <span>   ...   </span> : ''}
            {(index < lastpage) ? <Link to={`/explorer/${this.state.type}/?limit=${pagesize}&page=${index + 1}`}>Next</Link> : ''}
          </div>)
        return;
      }
    } catch (err) { console.error(err); }
    this.state.pageLinks = <br />
  }


  async getDataForRoute(forceUpdate = false) {
    //individual block and tx routes
    if (this.state.type == 'Tx' || this.state.type == 'Block' || this.state.type == 'Genesis') {
      if (
        !this.state.collecting
        && (
          forceUpdate
          || (this.state.lib.get(this.state.param) == undefined)
          //|| (confirmations < confirmationsneeded)
        )
      ) {
        this.setState({ collecting: true })
        let newData = {}; 
        if (this.state.type == 'Genesis')
          try { newData = await Actions[`getGenesisBlockDetail`]('000000c1f997ef7feee72e7aaa24f33fb94666c7c5cb9806a3bc63437b4e3479') } catch (err) { }
        else
          try { newData = await Actions[`get${this.state.type}Detail`](this.state.param) } catch (err) { }

        if (Object.keys(newData).length > 2) {
          Object.assign(newData, { id: this.state.param, prim: this.state.type.toLowerCase() })
          this.state.lib.set(this.state.param, newData)
          this.setState({ temp: newData, collecting: false })
        } else setTimeout(() => {
          this.setState({ collecting: false }, () => this.handleSwitch());
        }, 1000)
      }
    }

    // list page routes for blocks and transactions
    if (
        (this.state.path != this.state.listpageData.path) && 
        !this.state.collecting && 
        ((this.state.type.toLowerCase().indexOf('blocks') != -1) || 
          (this.state.type.toLowerCase().indexOf('transactions') != -1))
       ) 
    {
      let search = this.state.search
      let type = this.state.type.toLowerCase()
      let blocktag = ''
      if (type.toLowerCase().indexOf('transactions') != -1)
        type = 'tx'
      if (this.state.type.toLowerCase().indexOf('blocks') != -1) {
        if (type.indexOf('poa') != -1) blocktag = `PoA`
        if (type.indexOf('pos') != -1) blocktag = `PoS`
        if (type.indexOf('pow') != -1) blocktag = `PoW`
        blocktag = blocktag.length ? `minetype=${blocktag}` : ''
        type = 'block';
        if (blocktag.length)
          search = search.replace('?', '').length ? search + `&${blocktag}` : `${blocktag}`
      }

      this.state.collecting = true;
      if (search.length && (search.indexOf('?') == -1)) 
        search = `?${search}`
      let newData = {}; 
      try { newData = await Actions.getList(type, search) } catch (err) { }
      if (Object.keys(newData).length) {
        Object.assign(newData, { path: this.state.path, prim: type })
        // Set state with new listData, then retreive detailed data for table entries 
        await this.getListPageLinks();
        this.setState({ listpageData: newData, collecting: false, typemin: blocktag, prim: type},
          () => {
            if (newData.ids) {
              newData.ids.forEach((id) => {
                let prim = this.state.prim.charAt(0).toUpperCase() + this.state.prim.slice(1);
                if (this.state.lib.get(id) == undefined) {
                  let get = Actions[`get${prim}Detail`](id)
                  get.then(newData => {
                    if (Object.keys(newData).length > 2) {
                      Object.assign(newData, { id: id, prim: this.state.prim.toLowerCase() })
                      this.state.lib.set(id, newData)
                    }
                  })
                }
              })
            }
          })
      } else setTimeout(() => {
        this.setState({ collecting: false });
      }, 2000)
    }
  }

  async handleSwitch(forceRefresh = false) {
    //  result from React BrowserRouter regex in src/index.js:
    //      www.example.com/.../explorer/tx/:id?examplevar=exampleval
    //                props.match.params[0] = explorer/
    //                props.match.params[1] = tx/
    //                props.match.params[2] = 12345678987654321
    //                props.location.search = ?examplevar=exampleval
    let param = this.props.match.params[2] || '0',
      search = this.props.location.search || '',
      type = this.props.match.params[1].replace(/[^\w]/g, '').toLowerCase();
    type = type.charAt(0).toUpperCase() + type.slice(1);
    if (type == 'Genesis')
      param = 'genesis';
    let path = Object.values(this.props.match.params).join('') + search
    let pageindex = search.match(/page=[\d]*/g) || ''; pageindex = pageindex.length ? pageindex[0].replace('page=', '') : 0
    this.getDataForRoute(forceRefresh)
    if (forceRefresh || (this.state.path != path)) {
      // await this.getListPageLinks();
      this.setState({
        [`current${type}`]: param,
        param: param,
        search: search,
        type: type,
        lastpath: this.state.path,
        path: path,
        pageindex: parseInt(pageindex),
        // pagesize: (path.indexOf('limit')!=-1)? path.replace(/(limit=(\d+))/g,'').replace(/[^\d]/g,'') : pagesize
      })
    }
  }


  render() {
    return (<div id="BlockExplorer" className={"App " + Style.BlockExplorer}>
      <NavBar pagesize={this.state.pagesize} />

      <div className={"PageView " + Style.PageView}>

        <StatusBar id="blockStatusBar" getData={Actions.getBlockDetailData} className={`StatusBar ${Style.StatusBar}`}
          lift={(blockstate) => { Object.keys(blockstate).forEach((key) => Object.assign(this.state.blockStatus, { [key]: blockstate[key] })); 
          }} />

        <div className={"CenterView " + Style.CenterView}>
          <SearchBar lib={this.state.lib} isMobile={this.state.isMobile} />

          <div className={"ScreenView " + Style.ScreenView}>

            <Switch onChange={this.handleSwitch()}>
              <Route exact path={route + "overview/"} component={OverviewPage} />

              <Route exact path={route + "blocks/"} component={() =>
                <ListPage
                  data={this.state.listpageData}
                  title={`Blocks ${this.state.pageindex ? `Page ${this.state.pageindex}` : ''}`}
                  links={this.state.pageLinks}
                />}
              />

              <Route exact path={route + "Poablocks/"} component={() => <ListPage data={this.state.listpageData} title="PoA Blocks" links={this.state.pageLinks} />} />
              <Route exact path={route + "Posblocks/"} component={() => <ListPage data={this.state.listpageData} title="PoS Blocks" links={this.state.pageLinks} />} />
              <Route exact path={route + "powblocks/"} component={() => <ListPage data={this.state.listpageData} title="PoW Blocks" links={this.state.pageLinks} />} />

              <Route exact path={route + "transactions"} component={() => <ListPage data={this.state.listpageData} title="Transactions" links={this.state.pageLinks} />} />

              <Route exact path={route + "tx/:id"} component={() => <TxDetail data={this.state.lib.get(this.state.param)} back={this.state.lastpath} />} />
              <Route exact path={route + "block/:hash"} component={() => <BlockDetail data={this.state.lib.get(this.state.param)} back={this.state.lastpath} />} />
              <Route exact path={route + "genesis/"} component={() => <Genesis data={this.state.lib.get(this.state.param)} back={this.state.lastpath} />} />
            </Switch>

          </div>

        </div>

        <StatusBar id="networkStatusBar" getData={Actions.getNetworkDetailData} className={`StatusBar ${Style.StatusBar}`}
          // lift={(netstate) => { Object.keys(netstate).forEach((key) => Object.assign(this.state.netStatus, { [key]: netstate[key] })) }} />
          lift={(netstate) => { this.setState({netStatus: netstate}) }} />
      </div>

      <Footer data={this.state.netStatus}/>
    </div>
    )
  }
}

BlockExplorer.proptypes = { label: PropTypes.string }


export default BlockExplorer;
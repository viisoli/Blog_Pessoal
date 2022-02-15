import React from 'react';
import {Box, Button, Paper} from '@material-ui/core'
import './Home.css';

function Home(){
    return(
        <>
            <Paper>
                <Box p={2}>
                    <Box display="flex" justifyContent="center">
                        <h1>Titulo</h1>
                    </Box>
                    <img src="https://storage.googleapis.com/atados-v3/user-uploaded/images/8010b1b6-32bc-4dd4-bc11-a4a607c9974c.png" alt="logo" style={{width:"100%", height:"100%"}}/>
                    <Box display="flex" justifyContent="center" p={2}>
                        <Button variant = "contained" color="primary">texto1</Button>
                        <Button variant = "contained" color="secondary">texto2</Button>
                    </Box>
                </Box>
            </Paper>
        </>
    );
}

export default Home;